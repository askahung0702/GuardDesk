"""Validate browser-provided upload evidence; never open the reported file."""
import ntpath
import re
from urllib.parse import urlsplit,urlunsplit

PHASES={'started','response','failed','redirected','interrupted'}


def destination(value,sanitize_url):
    cleaned=sanitize_url(value)
    if not cleaned:return None
    safe,domain=cleaned
    if len(safe.encode('utf-8'))>2048:
        parsed=urlsplit(safe);return urlunsplit((parsed.scheme,parsed.netloc,'/','','')),domain,True
    return safe,domain,False


def upload_details(message, sanitize_url):
    phase=message.get('phase')
    if phase not in PHASES:raise ValueError('Invalid upload phase')
    flow=message.get('upload_id')
    if not isinstance(flow,str) or not re.fullmatch(r'[a-zA-Z0-9-]{1,100}',flow):raise ValueError('Invalid upload identity')
    files=message.get('files')
    if not isinstance(files,list) or not 1<=len(files)<=32:raise ValueError('Invalid upload files')
    checked=[];path_bytes=0;truncated=message.get('files_truncated') is True
    for item in files:
        if not isinstance(item,dict) or set(item) not in ({'path'},{'path','evidence'}):raise ValueError('Invalid upload file metadata')
        evidence=item.get('evidence','browser_request_file')
        if evidence not in ('browser_request_file','selected_filename_match','page_body_metadata_candidate'):raise ValueError('Invalid file evidence')
        path=item['path']
        if not isinstance(path,str) or not 1<=len(path)<=4096 or any(ord(c)<32 for c in path):raise ValueError('Invalid upload path')
        # Browser-provided paths are evidence only, never filesystem authority.
        # A basename/fakepath cannot be promoted to an absolute local path.
        drive,tail=ntpath.splitdrive(path)
        full=bool(evidence=='browser_request_file' and drive and tail.startswith(('\\','/')) and not path.startswith(('\\\\?\\','\\\\.\\')) and not re.search(r'(^|[\\/])fakepath([\\/]|$)',path,re.I))
        name=ntpath.basename(path)[:512]
        if len((path+name).encode('utf-8'))+path_bytes>2000:
            full=False;truncated=True
        item={'source_path':path if full else '', 'file_name':name,
                        'path_evidence':'browser_request_file' if full else evidence if evidence in ('selected_filename_match','page_body_metadata_candidate') else 'filename_only'}
        if len((item['source_path']+name).encode('utf-8'))+path_bytes>2000:truncated=True;break
        path_bytes+=len((item['source_path']+name).encode('utf-8'));checked.append(item)
    cleaned=destination(message.get('url',''),sanitize_url)
    if not cleaned:raise ValueError('Invalid upload destination')
    method=message.get('method')
    if method not in ('POST','PUT','PATCH'):raise ValueError('Invalid upload method')
    result={'upload_id':flow,'phase':phase,'files':checked,'url':cleaned[0],'domain':cleaned[1],
            'method':method,'source':'browser_webrequest','correlation':'page_body_metadata_candidate' if any(f['path_evidence']=='page_body_metadata_candidate' for f in checked) else 'selected_filename_candidate' if any(f['path_evidence']=='selected_filename_match' for f in checked) else 'same_browser_request_id',
            'application_success':'unknown','file_count':len(checked),'files_truncated':truncated,'url_truncated':cleaned[2] or message.get('url_truncated') is True}
    origin=message.get('site_origin')
    if origin:
        if not isinstance(origin,str) or len(origin)>2048:raise ValueError('Invalid initiating origin')
        p=urlsplit(origin)
        if p.scheme not in ('http','https') or not p.hostname or p.username or p.password or p.path not in ('','/') or p.query or p.fragment:raise ValueError('Invalid initiating origin')
        result['site_origin']=p.scheme+'://'+p.netloc
    if result['correlation']=='page_body_metadata_candidate':result['evidence_limit']='page_visible_metadata_not_browser_attested_file_identity'
    if len(checked)==1:result.update(checked[0])
    else:result['source_path']='\n'.join(f['source_path'] or f['file_name'] for f in checked)
    response=destination(message.get('response_url',''),sanitize_url)
    if response:result.update(response_url=response[0],response_url_truncated=response[2] or message.get('response_url_truncated') is True)
    if phase=='response':
        code=message.get('status_code')
        if type(code) is not int or not 100<=code<=599:raise ValueError('Invalid HTTP status')
        result.update(status_code=code,outcome='http_response_completed')
    elif phase=='failed':
        error=message.get('error')
        if not isinstance(error,str) or not re.fullmatch(r'net::[A-Z0-9_]{1,100}',error):error='browser_network_error'
        result.update(error=error,outcome='network_failed')
    elif phase=='redirected':
        redirect=destination(message.get('redirect_url',''),sanitize_url)
        if redirect:result.update(redirect_url=redirect[0],redirect_url_truncated=redirect[2] or message.get('redirect_url_truncated') is True)
    else:result['outcome']='request_observed' if phase=='started' else 'completion_not_observed'
    return result
