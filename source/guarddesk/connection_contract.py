"""Public endpoint connection schema, without center enrollment state."""
import re

def validate_body(body):
    if not isinstance(body,dict) or type(body.get('version')) is not int or body['version'] not in (1,2,3):
        raise ValueError('端點連線檔版本不正確')
    expected={'version','server','ca','ca_sha256'} | ({'deployment_code'} if body['version']>=2 else set()) | ({'browser_deployment','browser_deployment_authorization'} if body['version']==3 else set())
    if set(body)!=expected: raise ValueError('端點連線檔欄位不正確')
    if body['version']>=2 and (not isinstance(body['deployment_code'],str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}',body['deployment_code'])):
        raise ValueError('共用部署碼格式不正確')
    if body['version']==3:
        from .browser_deployment import validate
        validate(body['browser_deployment'])
        auth=body['browser_deployment_authorization']
        if not isinstance(auth,dict) or set(auth)!={'format','signature'} or type(auth['format']) is not int or auth['format']!=1 or not isinstance(auth['signature'],str) or len(auth['signature'])>128:raise ValueError('部署授權簽章格式不正確')

