"""Pure policy evaluation shared by the console and endpoint."""
from pathlib import Path
import copy
import re

DEFAULT_POLICY = {
    "mode": "monitor", "allow_export": True,
    "blocked_extensions": [".pem", ".key"],
    "keywords": ["機密", "CONFIDENTIAL"], "max_export_mb": 10,
    "usb_mode": "allow",
    "file_audit": {"enabled": True, "scope": "all_local", "exclude_paths": []},
    "browser_audit": True,
    "upload_rules": [],
    "website_control": {"enabled": False, "browsers": ["chrome", "edge"], "blocked": [], "allowed": []},
    "application_publishers": [],
    "application_audit": True,
    "application_audit_exclusions": [],
    "application_control": {"enabled": False, "mode": "denylist", "block_msi": False, "rules": []},
}
MAX_FILE = 10 * 1024 * 1024


def validate_policy(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULT_POLICY):
        raise ValueError("策略欄位不正確")
    if value["mode"] not in ("monitor", "enforce") or type(value["allow_export"]) is not bool:
        raise ValueError("策略模式不正確")
    for key in ("blocked_extensions", "keywords"):
        items = value[key]
        if not isinstance(items, list) or len(items) > 50 or any(not isinstance(s, str) or not s.strip() or len(s) > 100 for s in items):
            raise ValueError("規則最多 50 項，每項 1–100 字")
    if any(not s.startswith(".") or any(c in s for c in "/\\*") for s in value["blocked_extensions"]):
        raise ValueError("副檔名請使用 .pdf 格式")
    if type(value["max_export_mb"]) is not int or not 1 <= value["max_export_mb"] <= 10:
        raise ValueError("單檔上限須為 1–10 MB")
    if value['usb_mode'] not in ('allow', 'read_only', 'block') or type(value['browser_audit']) is not bool:
        raise ValueError('USB／瀏覽器設定不正確')
    audit = value['file_audit']
    if not isinstance(audit, dict) or set(audit) != {'enabled', 'scope', 'exclude_paths'} or type(audit['enabled']) is not bool or audit['scope'] not in ('all_local', 'managed'):
        raise ValueError('檔案稽核範圍不正確')
    if not isinstance(audit['exclude_paths'], list) or len(audit['exclude_paths']) > 100 or any(not isinstance(p,str) or not p.strip() or len(p)>500 for p in audit['exclude_paths']):
        raise ValueError('排除路徑最多 100 項')
    from .file_exclusions import validate_user_path_rules
    validate_user_path_rules(audit['exclude_paths'])
    from .file_access import options
    options(audit['exclude_paths'])
    rules = value['upload_rules']
    if type(value['application_audit']) is not bool:raise ValueError('應用程式稽核設定不正確')
    from .application_exclusions import validate_exclusions
    validate_exclusions(value['application_audit_exclusions'])
    from .category_rules import website,publishers
    website(value['website_control']);publishers(value['application_publishers'])
    validate_app_control(value['application_control'],allow_empty=bool(value['application_publishers']))
    if value['application_publishers'] and (not value['application_control']['enabled'] or value['application_control']['mode']!='denylist'):raise ValueError('分類發行者規則須搭配已啟用的程式黑名單')
    if not isinstance(rules,list) or len(rules)>50:
        raise ValueError('上傳規則最多 50 項')
    identities=set()
    for rule in rules:
        if not isinstance(rule,dict) or set(rule) != {'type','target','rate_kbps'} or rule['type'] not in ('domain','app','user'):
            raise ValueError('上傳規則必須為 domain、app 或 user')
        target=rule['target']
        if not isinstance(target,str) or len(target)>240 or not target.strip() or any(ord(c)<32 for c in target):
            raise ValueError('上傳目標不正確')
        if type(rule['rate_kbps']) is not int or not 8<=rule['rate_kbps']<=10000000:
            raise ValueError('上傳速率必須為 8–10000000 Kbit/s')
        if rule['type']=='domain' and not re.fullmatch(r'(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}',target):
            raise ValueError('網站請填網域，例如 example.com 或 *.example.com')
        if rule['type']=='app' and (not target.lower().endswith('.exe') or any(c in target for c in '*?"<>|')):
            raise ValueError('應用程式請填 .exe 名稱或完整路徑')
        if rule['type']=='user' and not re.fullmatch(r'[^\\/\[\]:;|=,+*?<>"\s]+\\[^\\/\[\]:;|=,+*?<>"\s]+',target):
            raise ValueError('使用者請填 DOMAIN\\account 或 COMPUTER\\account')
        identity=(rule['type'],target.casefold())
        if identity in identities:
            raise ValueError('上傳規則目標不可重複')
        identities.add(identity)
    return value


def validate_app_control(control,allow_empty=False):
    if not isinstance(control,dict) or set(control)!={'enabled','mode','block_msi','rules'} or type(control['enabled']) is not bool or type(control['block_msi']) is not bool or control['mode'] not in ('denylist','allowlist'):
        raise ValueError('應用程式控制設定不正確')
    if not isinstance(control['rules'],list) or len(control['rules'])>100:raise ValueError('應用程式規則最多 100 筆')
    seen=set()
    for rule in control['rules']:
        if not isinstance(rule,dict) or set(rule)!={'type','value','name','collection'} or rule['type'] not in ('path','sha256') or rule['collection'] not in ('Exe','Msi'):
            raise ValueError('程式規則須指定 path／sha256 及 Exe／Msi')
        name=rule['name'];target=rule['value']
        if not isinstance(name,str) or not name.strip() or len(name)>120 or any(ord(c)<32 for c in name):raise ValueError('程式規則名稱不正確')
        if not isinstance(target,str) or len(target)>500 or any(ord(c)<32 for c in target):raise ValueError('程式規則目標不正確')
        if rule['type']=='sha256':
            if not re.fullmatch('[a-fA-F0-9]{64}',target):raise ValueError('SHA-256 必須是 64 位十六進位字元')
        else:
            import ntpath
            suffix=ntpath.splitext(target)[1].lower()
            if suffix not in (('.exe','.com') if rule['collection']=='Exe' else ('.msi','.msp','.mst')) or any(c in target for c in '"<>|?%') or not (re.match(r'^[A-Za-z]:\\',target) or target.startswith('*\\')) or ntpath.basename(target).startswith('*'):
                raise ValueError('路徑須為完整 Windows 路徑或 *\\程式.exe；檔名不可使用萬用字元')
            # A blacklist must never disable Windows or this management agent.
            if control['mode']=='denylist' and (target.lower().startswith(('c:\\windows\\','c:\\program files\\guarddeskpilot\\')) or ntpath.basename(target).lower() in ('guarddesk.exe','powershell.exe','pwsh.exe','svchost.exe','winlogon.exe','lsass.exe','services.exe','explorer.exe')):
                raise ValueError('不能封鎖系統維運或 GuardDesk 程式')
        identity=(rule['collection'],rule['type'],target.casefold())
        if identity in seen:raise ValueError('程式規則不可重複')
        seen.add(identity)
    if control['enabled'] and control['mode']=='denylist' and not control['rules'] and not control['block_msi'] and not allow_empty:raise ValueError('黑名單啟用時至少設定一條規則或禁止 MSI 安裝')
    return control


def normalize_policy(value):
    """Read legacy 0.1 policies without silently accepting unknown fields."""
    result=copy.deepcopy(DEFAULT_POLICY)
    result.update(value)
    return validate_policy(result)


def agent_policy_wire(packet):
    """Keep the pre-0.4.27 body schema for installed strict legacy Agents."""
    packet=copy.deepcopy(packet)
    body=normalize_policy(packet['body'])
    packet['target_controls']={'format':1,'website_control':body.pop('website_control'),'application_publishers':body.pop('application_publishers'),'application_control':copy.deepcopy(body['application_control'])}
    if packet['target_controls']['application_publishers'] and not body['application_control']['rules'] and not body['application_control']['block_msi']:
        # A strict legacy Agent rejects an enabled empty denylist. The actual
        # publisher-only policy is restored only by a supporting decoder.
        body['application_control']=copy.deepcopy(DEFAULT_POLICY['application_control'])
    # 0.4.53 rejects unknown file-access reserved rules. Keep its strict body
    # valid and carry new options in an ignored, versioned packet projection.
    from .file_access import ALL_ACCESSES,INTERVAL
    full_paths=body['file_audit']['exclude_paths']
    extra=[r for r in full_paths if r==ALL_ACCESSES or r.startswith(INTERVAL)]
    positions=[i for i,r in enumerate(full_paths) if r==ALL_ACCESSES or r.startswith(INTERVAL)]
    body['file_audit']['exclude_paths']=[r for r in body['file_audit']['exclude_paths'] if r not in extra]
    packet.pop('file_access_options',None)
    if extra:packet['file_access_options']={'format':1,'rules':extra,'positions':positions}
    rules=body.pop('application_audit_exclusions')
    packet.update(body=body,audit_options={'application_exclusions':rules})
    if 'user_policies' in packet:
        packet['user_policies']={k:agent_policy_wire(v) for k,v in packet['user_policies'].items()}
        # New machine-only lists travel once, not once per reported account.
        for child in packet['user_policies'].values():
            child['target_controls']={'format':1,'website_control':copy.deepcopy(DEFAULT_POLICY['website_control']),'application_publishers':[],'application_control':copy.deepcopy(DEFAULT_POLICY['application_control'])}
    return packet


def decode_agent_policy(packet):
    """Decode in memory only; retain the legacy-compatible wire packet on disk."""
    packet=copy.deepcopy(packet);body=normalize_policy(packet['body'])
    if 'target_controls' in packet:
        extra=packet['target_controls']
        if not isinstance(extra,dict) or set(extra)!={'format','website_control','application_publishers','application_control'} or type(extra['format']) is not int or extra['format']!=1:raise ValueError('網站與應用分類協定不正確')
        body['website_control']=extra['website_control'];body['application_publishers']=extra['application_publishers'];body['application_control']=extra['application_control']
        validate_policy(body)
    if 'file_access_options' in packet:
        extra=packet['file_access_options']
        from .file_access import ALL_ACCESSES,INTERVAL
        if not isinstance(extra,dict) or set(extra)!={'format','rules','positions'} or type(extra['format']) is not int or extra['format']!=1 or not isinstance(extra['rules'],list) or not 1<=len(extra['rules'])<=2 or any(not isinstance(r,str) or not (r==ALL_ACCESSES or r.startswith(INTERVAL)) for r in extra['rules']):raise ValueError('文件互動選項格式不正確')
        positions=extra['positions']
        if not isinstance(positions,list) or len(positions)!=len(extra['rules']) or any(type(i) is not int or not 0<=i<100 for i in positions) or positions!=sorted(set(positions)):raise ValueError('文件互動選項位置不正確')
        for i,rule in zip(positions,extra['rules']):
            if i>len(body['file_audit']['exclude_paths']):raise ValueError('文件互動選項位置超出範圍')
            body['file_audit']['exclude_paths'].insert(i,rule)
        validate_policy(body)
    if 'audit_options' in packet:
        options=packet['audit_options']
        if not isinstance(options,dict) or set(options)!={'application_exclusions'}:raise ValueError('應用程式稽核選項不正確')
        body['application_audit_exclusions']=options['application_exclusions']
        validate_policy(body)
    packet['body']=body
    if 'user_policies' in packet:
        packet['user_policies']={k:decode_agent_policy(v) for k,v in packet['user_policies'].items()}
        for child in packet['user_policies'].values():
            for key in ('website_control','application_publishers','application_control'):
                child['body'][key]=copy.deepcopy(body[key])
            validate_policy(child['body'])
    return packet


def evaluate(policy, filename, data):
    validate_policy(policy)
    reasons = []
    if not policy["allow_export"]:
        reasons.append("export_disabled")
    if Path(filename).suffix.lower() in [s.lower() for s in policy["blocked_extensions"]]:
        reasons.append("blocked_extension")
    if len(data) > policy["max_export_mb"] * 1024 * 1024:
        reasons.append("size_limit")
    # Keyword detection covers plain UTF-8/UTF-16 text only; no PDF/Office/OCR claim.
    text = data.decode("utf-8", errors="ignore").casefold()
    text16 = data.decode("utf-16-le", errors="ignore").casefold()
    if any(s.casefold() in text or s.casefold() in text16 for s in policy["keywords"]):
        reasons.append("sensitive_keyword")
    return {"allowed": not reasons or policy["mode"] == "monitor", "matched": bool(reasons),
            "reasons": reasons, "mode": policy["mode"]}
