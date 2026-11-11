"""Loopback explicit proxy: throttle outgoing bytes without decrypting HTTPS."""
import getpass
import ipaddress
import select
import socket
import socketserver
import threading
import time
from urllib.parse import urlsplit


def domain_matches(host,target):
    host=host.lower().rstrip('.');target=target.lower().rstrip('.')
    return host.endswith(target[1:]) and host!=target[2:] if target.startswith('*.') else host==target


def matching_rate(host,rules):
    rates=[r['rate_kbps'] for r in rules if r['type']=='domain' and domain_matches(host,r['target'])]
    return min(rates) if rates else None


class SharedLimiter:
    def __init__(self,clock=time.monotonic):
        self.clock=clock;self.lock=threading.Lock();self.deadlines={}

    def delay(self,key,size,bits_per_second):
        with self.lock:
            now=self.clock()
            finish=max(now,self.deadlines.get(key,now))+size*8/bits_per_second
            self.deadlines[key]=finish
            return max(0,finish-now)


class GuardProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address=True;daemon_threads=True

    def __init__(self,address,agent,allow_loopback=False,ports=(80,443),max_connections=32):
        if address[0]!='127.0.0.1':raise ValueError('代理僅允許 loopback 監聽')
        super().__init__(address,ProxyConnection)
        self.agent=agent;self.limiter=SharedLimiter();self.stop_event=threading.Event()
        self.allow_loopback=allow_loopback;self.ports=set(ports)
        self._rules=[];self._rules_until=0;self._rules_lock=threading.Lock()
        self._slots=threading.BoundedSemaphore(max_connections)

    def rules(self):
        with self._rules_lock:
            if time.monotonic()>=self._rules_until:
                self._rules=self.agent.cached_policy()['body']['upload_rules'];self._rules_until=time.monotonic()+1
            return self._rules

    def process_request(self,request,address):
        if not self._slots.acquire(blocking=False):
            try:
                request.settimeout(.1)
                request.sendall(b'HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
            except OSError:pass
            self.shutdown_request(request);return
        try:super().process_request(request,address)
        except BaseException:
            self._slots.release();raise

    def process_request_thread(self,request,address):
        try:super().process_request_thread(request,address)
        finally:self._slots.release()

    def connect_target(self,host,port):
        if port not in self.ports:raise ValueError('Destination port not allowed')
        if matching_rate(host,self.rules()) is None:raise ValueError('Domain is not configured for this proxy')
        addresses=socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)
        for family,kind,protocol,_,address in addresses:
            ip=ipaddress.ip_address(address[0])
            if (ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast) and not self.allow_loopback:
                continue
            connection=socket.socket(family,kind,protocol)
            try:
                connection.settimeout(10);connection.connect(address);connection.settimeout(None);return connection
            except OSError:connection.close()
        raise OSError('No permitted destination address is reachable')

    def close(self):
        self.stop_event.set();self.shutdown();self.server_close()


class ProxyConnection(socketserver.BaseRequestHandler):
    def handle(self):
        remote=None;host='';sent=0;started=time.time();last_report=time.monotonic()
        self.request.settimeout(15)
        try:
            header=b''
            while b'\r\n\r\n' not in header:
                chunk=self.request.recv(4096)
                if not chunk:return
                header+=chunk
                if len(header)>65536:raise ValueError('Proxy header too large')
            raw,initial=header.split(b'\r\n\r\n',1)
            lines=raw.decode('iso-8859-1').split('\r\n')
            method,target,version=lines[0].split(' ',2)
            if version not in ('HTTP/1.0','HTTP/1.1'):raise ValueError('Unsupported HTTP version')
            if method=='CONNECT':
                parsed=urlsplit('//'+target);host=parsed.hostname;port=parsed.port or 443
                if not host or parsed.username or parsed.path:raise ValueError('Invalid CONNECT target')
                remote=self.server.connect_target(host,port)
                self.request.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                pending=initial
            else:
                parsed=urlsplit(target)
                if parsed.scheme!='http' or not parsed.hostname or parsed.username or parsed.fragment:raise ValueError('HTTP proxy expects absolute HTTP URL')
                host=parsed.hostname;port=parsed.port or 80
                remote=self.server.connect_target(host,port)
                path=parsed.path or '/'
                if parsed.query:path+='?'+parsed.query
                forwarded=[f'{method} {path} {version}']
                for line in lines[1:]:
                    if ':' not in line:raise ValueError('Invalid header')
                    if line.split(':',1)[0].lower() not in ('proxy-authorization','proxy-connection','connection','host'):
                        forwarded.append(line)
                forwarded += ['Host: '+host+(':'+str(port) if port!=80 else ''),'Connection: close']
                pending=('\r\n'.join(forwarded)+'\r\n\r\n').encode('iso-8859-1')+initial
            # Duplex, bounded nonblocking relay. Waiting for an upload quota
            # must not hold back a server response (100 Continue, HTTP/2 flow
            # control, early rejection, or an interactive response).
            self.request.setblocking(False);remote.setblocking(False)
            client_readable=True;remote_readable=True;write_closed=False
            incoming=b'';reserved=b'';send_at=0
            while not self.server.stop_event.is_set():
                now=time.monotonic()
                if pending and not reserved:
                    rules=self.server.rules()
                    rate=matching_rate(host,rules)
                    if rate is None:break
                    # Shared rule bucket across connections and matching subdomains.
                    matches=[r for r in rules if r['type']=='domain' and domain_matches(host,r['target'])]
                    delay=0
                    reserved,pending=pending[:1024],pending[1024:]
                    for rule in matches:
                        delay=max(delay,self.server.limiter.delay(('domain',rule['target'].lower()),len(reserved),rule['rate_kbps']*1000))
                    send_at=now+delay
                if not client_readable and not pending and not reserved and not write_closed:
                    remote.shutdown(socket.SHUT_WR);write_closed=True
                if not remote_readable and not incoming:break
                readers=([self.request] if client_readable and not pending and not reserved else [])+([remote] if remote_readable and not incoming else [])
                writers=([self.request] if incoming else [])+([remote] if reserved and now>=send_at else [])
                timeout=min(.25,max(0,send_at-now)) if reserved and now<send_at else .25
                ready,writable,_=select.select(readers,writers,[],timeout)
                if remote in ready:
                    chunk=remote.recv(65536)
                    if chunk:incoming=chunk
                    else:remote_readable=False
                if self.request in writable:
                    size=self.request.send(incoming);incoming=incoming[size:]
                if remote in writable:
                    # Recheck removals without bypassing the shared quota.
                    if matching_rate(host,self.server.rules()) is None:break
                    size=remote.send(reserved);reserved=reserved[size:];sent+=size
                if self.request in ready:
                    pending=self.request.recv(16384)
                    if not pending:client_readable=False
                if time.monotonic()-last_report>=30:
                    if sent:self.report(host,sent,started)
                    sent=0;started=time.time();last_report=time.monotonic()
        except (OSError,ValueError) as exc:
            if remote is None:
                try:self.request.sendall(b'HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
                except OSError:pass
            if host:self.server.agent.queue('network.proxy_error',{'domain':host,'error':str(exc)[:300]},'warning')
        finally:
            if remote:remote.close()
            if sent:self.report(host,sent,started)

    def report(self,host,count,started):
        self.server.agent.queue('network.upload',{'domain':host,'outgoing_bytes':count,'started':started,'finished':time.time(),
            'rate_kbps':matching_rate(host,self.server.rules()),'user':getpass.getuser(),'source':'loopback_proxy',
            'includes':'all_outgoing_tunnel_bytes_not_only_file_body'})


def pac_script(rules,port):
    import json
    domains=[r['target'].lower() for r in rules if r['type']=='domain']
    return 'function FindProxyForURL(url, host) { host=host.toLowerCase(); var domains='+json.dumps(domains)+'; for(var i=0;i<domains.length;i++){var d=domains[i];if(d.indexOf("*.")===0?host.endsWith(d.slice(1)):host===d)return "PROXY 127.0.0.1:'+str(int(port))+'";}return "DIRECT";}'
