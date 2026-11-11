"""Typed category targets. Host globs never pass unchecked to browser policy."""
import copy
import hashlib
import json
import re
import csv
import io
import fnmatch
from urllib.parse import urlsplit
from functools import lru_cache

WEBSITE_DEFAULT={'enabled':False,'browsers':['chrome','edge'],'blocked':[],'allowed':[]}


def host_pattern(value):
    if not isinstance(value,str) or not value or len(value)>253 or value!=value.strip():
        raise ValueError('網站模式須為 1–253 字，不含空白或網址路徑')
    labels=[]
    for label in value.rstrip('.').split('.'):
        if '*' in label:
            if not re.fullmatch(r'[a-zA-Z0-9*\-]+',label):raise ValueError('含 * 的網域區段僅接受英文字母、數字及連字號')
            label=re.sub(r'\*+','*',label).lower()
        else:
            try:label=label.encode('idna').decode('ascii').lower()
            except UnicodeError:raise ValueError('網站模式格式不正確') from None
            if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label):raise ValueError('網站模式格式不正確')
        if len(label)>63:raise ValueError('網域區段最多 63 字')
        labels.append(label)
    result='.'.join(labels)
    if '*' not in result or len(result)>253 or result.count('*')>16 or len(result.replace('*','').replace('.','').replace('-',''))<2:
        raise ValueError('請填寫含網站名稱的 * 模式；不接受全網 * 或超過 16 個萬用字元')
    return result


def pattern_matches(pattern,host):
    # Only '*' is accepted by host_pattern; [], ?, regex and URL paths are not.
    return fnmatch.fnmatchcase(host,pattern) or (pattern.startswith('*.') and fnmatch.fnmatchcase(host,pattern[2:]))


def glob_native_domains(item):
    pattern=item['pattern']
    if pattern.startswith('*.') and '*' not in pattern[2:]:
        try:return [domain(pattern[2:])],True
        except ValueError:pass  # e.g. *.com: classification only, needs explicit hosts.
    return item['enforcement_domains'],False


def website_capability(item):
    if item['type']=='domain':return {'mode':'native','coverage':'complete','filters':[compile_member(item)]}
    domains,complete=glob_native_domains(item)
    prefix='' if item['scheme']=='any' else item['scheme']+'://'
    # A leading '*' guarantees every subdomain also matches. Other patterns
    # get exact-host filters so a supplied host cannot silently broaden scope.
    filters=[prefix+('' if item['pattern'].startswith('*') else '.')+d for d in domains]
    return {'mode':'native' if complete else 'explicit_domains' if domains else 'unavailable',
            'coverage':'complete' if complete else 'selected_domains_only' if domains else 'unconfigured','filters':filters}


def match_preview(body):
    if not isinstance(body,dict) or set(body)!={'members','urls'}:raise ValueError('比對預覽欄位不正確')
    if not isinstance(body['members'],list) or len(body['members'])>1000 or not isinstance(body['urls'],list) or not 1<=len(body['urls'])<=10:
        raise ValueError('比對預覽最多 1000 個成員及 10 個網址')
    items=[member('website',m) for m in body['members']];results=[]
    for url in body['urls']:
        if not isinstance(url,str) or len(url)>2048 or any(ord(c)<33 for c in url):raise ValueError('請填寫 HTTP／HTTPS 網址，不含空白')
        try:
            parsed=urlsplit(url)
            if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username is not None or parsed.password is not None:raise ValueError()
            parsed.port
            host=domain(parsed.hostname)
        except ValueError:raise ValueError('請填寫有效的 HTTP／HTTPS 網域網址，不含帳密') from None
        hits=[]
        for item in items:
            if item['scheme'] not in ('any',parsed.scheme):continue
            matches=pattern_matches(item['pattern'],host) if item['type']=='host_glob' else host==item['domain'] or item['include_subdomains'] and host.endswith('.'+item['domain'])
            if matches:
                capability=website_capability(item)
                enforced=any(host==f.split('://')[-1].lstrip('.') or not f.split('://')[-1].startswith('.') and host.endswith('.'+f.split('://')[-1]) for f in capability['filters'])
                hits.append({'id':item['id'],'name':item['name'],'native_covered':enforced,
                             'mode':capability['mode'],'coverage':capability['coverage'],'filter_count':len(capability['filters'])})
        # Do not echo paths/query strings, nor write preview URLs into audit logs.
        results.append({'host':host,'scheme':parsed.scheme,'matches':hits})
    return {'results':results,'scope':'category_match_only_not_navigation_verification'}


def domain(value):
    if not isinstance(value,str) or not value or len(value)>253 or value!=value.strip():
        raise ValueError('請填寫網域，不含網址路徑或萬用字元')
    return _domain_text(value)


@lru_cache(maxsize=4096)
def _domain_text(value):
    try:result=value.rstrip('.').encode('idna').decode('ascii').lower()
    except UnicodeError:raise ValueError('網域格式不正確') from None
    if len(result)>253 or '.' not in result or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in result.split('.')):
        raise ValueError('請填寫完整網域，例如 example.com；不支援網址或 * 萬用字元')
    # Reject IP-like hosts in this version rather than broadening native syntax.
    if result.split('.')[-1].isdigit():raise ValueError('首版請使用網站網域，不接受 IP 規則')
    return result


def filter_text(value):
    if not isinstance(value,str):raise ValueError('網站規則必須是文字')
    prefix=''
    for scheme in ('http://','https://'):
        if value.startswith(scheme):prefix=scheme;value=value[len(scheme):];break
    exact=value.startswith('.')
    if exact:value=value[1:]
    return prefix+('.' if exact else '')+domain(value)


def website(value):
    if not isinstance(value,dict) or set(value)!=set(WEBSITE_DEFAULT) or type(value['enabled']) is not bool:
        raise ValueError('網站存取管制欄位不正確')
    browsers=value['browsers']
    if not isinstance(browsers,list) or not 1<=len(browsers)<=2 or any(b not in ('chrome','edge') for b in browsers) or len(set(browsers))!=len(browsers):
        raise ValueError('請選擇 Chrome 或 Edge')
    for key in ('blocked','allowed'):
        rules=value[key]
        if not isinstance(rules,list) or len(rules)>1000:raise ValueError('每份網站清單最多 1000 筆，不可截斷')
        normalized=[filter_text(x) for x in rules]
        if normalized!=rules or len(set(normalized))!=len(rules):raise ValueError('網站規則需標準化且不可重複')
    return value


def publishers(value):
    from .custom_settings import validate,DEFAULT
    validate({**copy.deepcopy(DEFAULT),'software':value})
    return value


def merge_publishers(left,right):
    result=copy.deepcopy(left);seen={identity(x) for x in result}
    for item in right:
        key=identity(item)
        if key not in seen:result.append(copy.deepcopy(item));seen.add(key)
    return publishers(result)


def member(kind,item):
    if not isinstance(item,dict):raise ValueError('分類成員格式不正確')
    item=copy.deepcopy(item)
    common={'id','type','name'}
    name=item.get('name','')
    if not isinstance(name,str) or not name.strip() or len(name)>120 or any(ord(c)<32 for c in name):raise ValueError('成員名稱須為 1–120 字')
    typ=item.get('type')
    if kind=='website':
        if typ=='domain':
            if set(item)-common!={'domain','include_subdomains','scheme'}:raise ValueError('網站成員請指定網域、子網域與協定')
            if type(item['include_subdomains']) is not bool:raise ValueError('網站比對方式不正確')
            if isinstance(item['domain'],str) and '*' in item['domain']:
                # Accept existing editors / plain-text imports as well as the
                # explicit new type; preserve the actual pattern in storage.
                item.pop('include_subdomains');item['pattern']=item.pop('domain');item['type']=typ='host_glob'
                item['enforcement_domains']=[]
            else:item['domain']=domain(item['domain'])
        if typ=='host_glob':
            if set(item)-common!={'pattern','scheme','enforcement_domains'}:raise ValueError('網站模式欄位不正確')
            item['pattern']=host_pattern(item['pattern'])
            domains=item['enforcement_domains']
            if not isinstance(domains,list) or len(domains)>100:raise ValueError('每個模式最多設定 100 個實際封鎖網域')
            normalized=[domain(d) for d in domains]
            if len(set(normalized))!=len(normalized):raise ValueError('實際封鎖網域不可重複')
            if any(not pattern_matches(item['pattern'],d) for d in normalized):raise ValueError('實際封鎖網域必須符合此網站模式')
            item['enforcement_domains']=normalized
            if glob_native_domains(item)[1] and normalized:
                raise ValueError('*.完整網域 已涵蓋根網域及子網域，不需另填封鎖網域')
        elif typ!='domain':raise ValueError('網站成員類型不正確')
        if item['scheme'] not in ('any','http','https'):raise ValueError('網站比對方式不正確')
    elif kind=='application' and typ in ('path','sha256'):
        if set(item)-common!={'value','collection'}:raise ValueError('應用程式成員欄位不正確')
        from .policy import validate_app_control
        validate_app_control({'enabled':True,'mode':'denylist','block_msi':False,'rules':[{k:v for k,v in item.items() if k!='id'}]})
        if typ=='sha256':item['value']=item['value'].lower()
    elif kind=='application' and typ=='publisher':
        if set(item)-common!={'collection','publisher','product','binary','min_version','max_version'}:raise ValueError('發行者成員欄位不正確')
        publishers([{k:v for k,v in item.items() if k not in ('id','type')}])
    else:raise ValueError('分類與成員類型不符')
    # ID-less imports are deterministic and can be round-tripped without secrets.
    item.setdefault('id',hashlib.sha256(json.dumps(item,sort_keys=True,ensure_ascii=False).encode()).hexdigest()[:24])
    if not isinstance(item['id'],str) or not re.fullmatch('[0-9a-f]{24}',item['id']):raise ValueError('成員 ID 不正確')
    return item


def identity(item):
    return json.dumps({k:v for k,v in item.items() if k not in ('id','name')},sort_keys=True,ensure_ascii=False).casefold()


def compile_member(item):
    if item['type']=='domain':
        return ('' if item['scheme']=='any' else item['scheme']+'://')+('' if item['include_subdomains'] else '.')+item['domain']
    if item['type']=='host_glob':
        capability=website_capability(item)
        if not capability['filters']:
            raise ValueError('網站模式「'+item['pattern']+'」尚未設定實際封鎖網域；Chrome／Edge 不支援任意 *，不能發布為已管制')
        return capability['filters']
    return {k:v for k,v in item.items() if k not in ('id',)} if item['type']!='publisher' else {k:v for k,v in item.items() if k not in ('id','type')}


def import_members(kind,text,include_subdomains=True):
    if kind not in ('website','application') or not isinstance(text,str) or len(text)>500000 or type(include_subdomains) is not bool:raise ValueError('匯入內容或類型不正確')
    text=text.lstrip('\ufeff');errors=[];items=[];seen=set()
    if not text.strip():raise ValueError('匯入內容不可空白')
    lines=text.splitlines()
    if len(lines)>1001:raise ValueError('每次匯入最多 1000 筆')
    if ',' in lines[0]:
        try:
            reader=csv.DictReader(io.StringIO(text),strict=True);raw=list(reader)
        except csv.Error:raise ValueError('CSV 引號或資料列格式不正確') from None
        if len(set(reader.fieldnames or []))!=len(reader.fieldnames or []):raise ValueError('CSV 欄位重複')
        start=2
    elif kind=='website':raw=[{'name':s.strip(),'type':'domain','domain':s.strip(),'include_subdomains':include_subdomains,'scheme':'any'} for s in lines if s.strip()];start=1
    else:raise ValueError('應用程式請匯入含欄位名稱的 CSV')
    for index,row in enumerate(raw,start):
        try:
            row={k:v for k,v in row.items() if v not in ('',None)}
            if row.get('type')=='host_glob':
                raw_domains=row.get('enforcement_domains','[]')
                try:row['enforcement_domains']=json.loads(raw_domains)
                except (TypeError,ValueError):raise ValueError('實際封鎖網域欄位須為 JSON 清單') from None
            if 'include_subdomains' in row and isinstance(row['include_subdomains'],str):
                if row['include_subdomains'].lower() not in ('true','false'):raise ValueError('子網域欄位須為 true 或 false')
                row['include_subdomains']=row['include_subdomains'].lower()=='true'
            item=member(kind,row);key=identity(item)
            if key in seen:raise ValueError('重複成員')
            seen.add(key);items.append(item)
        except (ValueError,TypeError) as exc:errors.append({'line':index,'message':str(exc)[:180]})
    return {'members':items if not errors else [],'errors':errors,'valid_count':len(items),'publishable':not errors}


def export_members(items):
    fields=['id','name','type','domain','include_subdomains','scheme','pattern','enforcement_domains','collection','value','publisher','product','binary','min_version','max_version']
    out=io.StringIO(newline='');writer=csv.DictWriter(out,fieldnames=fields);writer.writeheader()
    for item in items:
        row={k:('true' if v is True else 'false' if v is False else v) for k,v in item.items()}
        if 'enforcement_domains' in row:row['enforcement_domains']=json.dumps(row['enforcement_domains'],ensure_ascii=False)
        # Neutralize spreadsheet formulas; import deliberately keeps this
        # marker instead of silently converting a potentially dangerous value.
        row={k:("'"+v if isinstance(v,str) and v.startswith(('=','+','-','@','\t','\r')) else v) for k,v in row.items()}
        writer.writerow(row)
    return out.getvalue()
