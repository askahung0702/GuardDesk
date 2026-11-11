"""Short-lived session/filter-bound snapshots carrying a stable event anchor.

The query layer resolves an anchor's immutable sort key; no path is put in URLs.
"""
import base64
import hashlib
import hmac
import json
import time


def filter_identity(query):
    return hashlib.sha256(json.dumps({k:v for k,v in sorted(query.items()) if k not in ('cursor','offset','request_id')},sort_keys=True,separators=(',',':')).encode()).hexdigest()


def encode(key, user, filters, snapshot, before):
    raw=json.dumps({'u':hashlib.sha256(user.encode()).hexdigest(),'f':filters,'s':snapshot,'b':before,'e':int(time.time())+900},sort_keys=True,separators=(',',':')).encode()
    return base64.urlsafe_b64encode(raw+hmac.digest(key,raw,'sha256')).decode().rstrip('=')


def decode(key, token, user, filters):
    try:
        if not isinstance(token,str) or len(token)>2048:raise ValueError()
        data=base64.b64decode(token+'='*(-len(token)%4),altchars=b'-_',validate=True)
        raw,signature=data[:-32],data[-32:]
        if not hmac.compare_digest(signature,hmac.digest(key,raw,'sha256')):raise ValueError()
        value=json.loads(raw)
        if value.get('u')!=hashlib.sha256(user.encode()).hexdigest() or value.get('f')!=filters or type(value.get('e')) is not int or value['e']<time.time():raise ValueError()
        if any(type(value.get(k)) is not int or not 0<=value[k]<=2**63-1 for k in ('s','b')):raise ValueError()
        if value['b']>value['s']+1:raise ValueError()
        return value['s'],value['b']
    except (ValueError,TypeError,UnicodeError,KeyError):
        raise ValueError('查詢游標無效或已過期，請重新搜尋') from None
