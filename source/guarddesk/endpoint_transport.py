"""Endpoint enrollment and bounded TLS transport, without collectors or center DB."""
import json
import os
import socket
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit
from .serialization import canonical
from .transport_errors import CenterTransportError, network_error

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args):return None


def transport(server,ca=None):
    handlers=[urllib.request.ProxyHandler({}),NoRedirect()]
    if urlsplit(server).scheme=='https':handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca)))
    return urllib.request.build_opener(*handlers)


def request(server, path, body, token=None, ca=None, opener=None,timeout=10):
    url = urlsplit(server)
    if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
        raise ValueError("管理中心網址須是 http(s)://主機:埠")
    if url.scheme == "http" and url.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("跨機連線必須使用 HTTPS")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(server.rstrip("/") + path, data=canonical(body).encode(), headers=headers, method="POST")
    # Never follow redirects with an endpoint bearer token.
    opener=opener or transport(server,ca)
    try:
        with opener.open(req, timeout=timeout) as response:
            return json.loads(response.read(1024 * 1024))
    except urllib.error.HTTPError as exc:
        code=exc.code;exc.close()
        raise CenterTransportError('http', http_status=code) from None
    except urllib.error.URLError as exc:
        raise network_error(exc.reason) from None
    except (TimeoutError, ConnectionResetError, ConnectionAbortedError, ssl.SSLError) as exc:
        raise network_error(exc) from None


def private_write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        stream.write(canonical(value))
    if os.name != "nt":
        path.chmod(0o600)


def enroll(config, server, token, watch, name=None, department="試用組", ca=None):
    config = Path(config).resolve()
    if config.exists():
        raise ValueError("設定檔已存在；請勿重複註冊")
    watch = Path(watch).resolve()
    if not watch.is_dir():
        raise ValueError("監看資料夾不存在")
    if config.is_relative_to(watch):
        raise ValueError("Agent 設定檔必須位於監看資料夾之外")
    result = request(server, "/api/agent/enroll", {"token": token, "name": name or socket.gethostname(), "department": department}, ca=ca)
    settings={"server": server, "token": result["token"], "device_id": result["device_id"], "watch": str(watch), "ca": ca}
    from . import remote_trial
    if remote_trial.enabled():settings['install_profile']=remote_trial.PROFILE
    private_write(config,settings)
    return result["device_id"]

