"""Optional authenticated company TURN policy; no destinations from viewer input.

Only protected center startup code constructs RelayAuthority. REST credentials
are short lived, role/session/cohort bound and memory only. TURN is additional
transport, never input authority. No public STUN, insecure TLS or config route.
"""
import base64
import hashlib
import hmac
import ipaddress
import json
import math
import re
import struct
import time

POLICY_KEYS={'mode','turn_ipv4','turn_port','tls_hostname','allocation_ipv4','allocation_port_min','allocation_port_max'}
VALUE_KEYS=POLICY_KEYS|{'policy_sha256','username','password','remaining_seconds'}

def require(value):
    if not value:raise ValueError('Native relay policy refused')

def ipv4(value,owned):
    require(isinstance(value,str))
    address=ipaddress.IPv4Address(value)
    require(str(address)==value and ((address.is_private and not (address.is_loopback or address.is_unspecified or address.is_link_local or address.is_multicast)) or (owned and address.is_loopback)))
    return address.packed

def policy(value,*,owned_loopback=False):
    require(isinstance(value,dict) and set(value)==POLICY_KEYS)
    require(value['mode']=='tls' or (owned_loopback and value['mode']=='owned_udp'))
    ipv4(value['turn_ipv4'],owned_loopback)
    require(type(value['turn_port']) is int and 0<value['turn_port']<=65535)
    hostname=value['tls_hostname']
    require(isinstance(hostname,str) and len(hostname)<=253)
    if value['mode']=='tls':
        require(hostname and any(c not in '0123456789.' for c in hostname) and all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',label) for label in hostname.split('.')))
    else:require(hostname=='')
    addresses=value['allocation_ipv4']
    require(isinstance(addresses,list) and 1<=len(addresses)<=4 and all(isinstance(v,str) for v in addresses) and len(set(addresses))==len(addresses))
    for address in addresses:ipv4(address,owned_loopback)
    require(type(value['allocation_port_min']) is int and type(value['allocation_port_max']) is int and 0<value['allocation_port_min']<=value['allocation_port_max']<=65535)
    return {**value,'allocation_ipv4':list(addresses)}

def validate(value,*,owned_loopback=False):
    require(isinstance(value,dict) and set(value)==VALUE_KEYS)
    policy({key:value[key] for key in POLICY_KEYS},owned_loopback=owned_loopback)
    require(isinstance(value['policy_sha256'],str) and re.fullmatch('[0-9a-f]{64}',value['policy_sha256']))
    for name,minimum,maximum in (('username',1,256),('password',16,512)):
        text=value[name];require(isinstance(text,str) and minimum<=len(text)<=maximum and all(33<=ord(c)<=126 for c in text))
    seconds=value['remaining_seconds'];require(type(seconds) in (int,float) and math.isfinite(seconds) and 0<seconds<=600)
    return value

def relay_identity(value,*,owned_loopback=False):
    if value is None:return None
    validate(value,owned_loopback=owned_loopback)
    return hashlib.sha256(json.dumps({k:v for k,v in value.items() if k!='remaining_seconds'},sort_keys=True,separators=(',',':')).encode('ascii')).digest()

def encode_relay(value,request_started_tick,now_tick,consent_deadline,*,owned_loopback=False):
    validate(value,owned_loopback=owned_loopback)
    require(all(type(v) is int and 0<=v<2**64 for v in (request_started_tick,now_tick,consent_deadline)))
    require(request_started_tick<=now_tick)
    deadline=min(consent_deadline,request_started_tick+int(value['remaining_seconds']*1000))
    require(now_tick<deadline and deadline-now_tick<=600000)
    hostname=value['tls_hostname'].encode('ascii');username=value['username'].encode('ascii');password=value['password'].encode('ascii')
    result=bytearray(128);result[:4]=b'GDR3'
    struct.pack_into('<HHII',result,4,1,1 if value['mode']=='tls' else 2,128+len(hostname)+len(username)+len(password),0)
    result[16:48]=bytes.fromhex(value['policy_sha256']);struct.pack_into('<Q',result,48,deadline)
    result[56:60]=ipv4(value['turn_ipv4'],owned_loopback)
    struct.pack_into('<HHHHI',result,60,value['turn_port'],len(hostname),len(username),len(password),len(value['allocation_ipv4']))
    for i,address in enumerate(value['allocation_ipv4']):result[72+4*i:76+4*i]=ipv4(address,owned_loopback)
    struct.pack_into('<HH',result,88,value['allocation_port_min'],value['allocation_port_max'])
    result.extend(hostname+username+password);require(len(result)<=1152)
    return bytes(result)

class RelayAuthority:
    """Construct only at protected center startup, never from an HTTP body."""
    def __init__(self,value,secret,*,owned_loopback=False,wall_clock=time.time):
        self.policy=policy(value,owned_loopback=owned_loopback)
        require(isinstance(secret,bytes) and 32<=len(secret)<=128)
        self.secret=secret;self.wall_clock=wall_clock;self.owned_loopback=owned_loopback
    def issue(self,session_id,cohort_sha256):
        require(isinstance(session_id,str) and re.fullmatch('[0-9a-f]{32}',session_id))
        require(isinstance(cohort_sha256,str) and re.fullmatch('[0-9a-f]{64}',cohort_sha256))
        now=self.wall_clock();require(type(now) in (int,float) and math.isfinite(now) and now>0)
        expires=math.floor(now)+600
        identity={**self.policy,'session_id':session_id,'cohort_sha256':cohort_sha256}
        policy_hash=hashlib.sha256(json.dumps(identity,sort_keys=True,separators=(',',':')).encode('ascii')).hexdigest()
        result={}
        for role in ('viewer','endpoint'):
            username=f'{expires}:{session_id}:{role}:1:{cohort_sha256}'
            # TURN REST interoperability: timestamped username and HMAC-SHA1,
            # per coturn README.turnserver. This is not a TLS/signature hash.
            password=base64.b64encode(hmac.new(self.secret,username.encode('ascii'),hashlib.sha1).digest()).decode('ascii')
            result[role]={**self.policy,'allocation_ipv4':list(self.policy['allocation_ipv4']),'policy_sha256':policy_hash,'username':username,'password':password}
        return result,expires
