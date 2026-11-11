"""Read-only DEV dispatch/context metadata, no credentials/history/config dump."""
import datetime,json,os,sqlite3,ssl,urllib.request,urllib.error,winreg
from contextlib import closing
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def main():
    runtime=Path(os.environ['LOCALAPPDATA'])/'GuardDeskPilotClient/runtime/agent'
    result={'observed_at':datetime.datetime.now().astimezone().isoformat(),'company_changed':False,'registry':{}}
    c=json.loads((runtime/'config.json').read_text(encoding='utf-8-sig'))
    result.update(server=c.get('server'),browser_deployment_in_user_config=bool(c.get('browser_deployment')),update_trust_in_user_config=bool(c.get('update_key')))
    for label,path in [('user',runtime/'runtime-health.json'),('native',Path(os.environ['ProgramData'])/'GuardDeskPilot/USBControl'/c['device_id']/'native-health.json')]:
        try:
            d=json.loads(path.read_text(encoding='utf-8'));result[label+'_health']={k:d.get(k) for k in ('version','time','pid')}
        except OSError as e:result[label+'_health']={'error':type(e).__name__,'winerror':getattr(e,'winerror',None)}
    with closing(sqlite3.connect((runtime/'config.sqlite3').as_uri()+'?mode=ro',uri=True,timeout=1)) as db:
        db.execute('PRAGMA query_only=ON')
        for key in ('policy','feature_status','document_browser_sessions_v1'):
            row=db.execute('SELECT value FROM state WHERE key=?',(key,)).fetchone();d=json.loads(row[0]) if row else None
            if key=='policy':result['received_policy']={k:d.get(k) for k in ('version','received')} if d else None;result['browser_audit']=d.get('body',{}).get('browser_audit') if d else None
            elif key=='feature_status' and isinstance(d,dict):
                result['user_collectors']={k:d.get(k) for k in ('document_upload','browser_native_host','document_native_read')}
            elif key=='document_browser_sessions_v1':result['browser_handshake_present']=bool(d)
    known_ids={'lmkhfmkcfgiblcplmoiakljcmnfhoekj'}
    if c.get('browser_deployment'):known_ids.add(c['browser_deployment']['extension_id'])
    for name,vendor in (('chrome',r'Google\Chrome'),('edge',r'Microsoft\Edge')):
        for hive,label in ((winreg.HKEY_CURRENT_USER,'HKCU'),(winreg.HKEY_LOCAL_MACHINE,'HKLM')):
            path='Software\\Policies\\'+vendor+'\\ExtensionInstallForcelist'
            try:
                with winreg.OpenKey(hive,path,0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY) as key:
                    found=[]
                    for i in range(min(1000,winreg.QueryInfoKey(key)[1])):
                        _,value,_=winreg.EnumValue(key,i)
                        if isinstance(value,str) and value.split(';')[0] in known_ids:found.append(value)
                    result['registry'][name+'_'+label]={'matching_policies':found}
            except FileNotFoundError:result['registry'][name+'_'+label]={'present':False}
            except OSError as e:result['registry'][name+'_'+label]={'error':type(e).__name__}
    context=ssl.create_default_context(cafile=c.get('ca'))
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
    try:
        with opener.open(c['server'].rstrip('/')+'/browser-extension/updates.xml',timeout=5) as response:
            data=response.read(8193);result['public_extension_publication']={'http_status':response.status,'bytes':len(data),'tls_verified':True}
    except urllib.error.HTTPError as e:result['public_extension_publication']={'http_status':e.code,'tls_verified':True};e.close()
    except (OSError,urllib.error.URLError) as e:result['public_extension_publication']={'error_type':type(e).__name__}
    output=ROOT/'evidence/maintenance'/('dispatch-local-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'.json')
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(result,ensure_ascii=False))

if __name__=='__main__':main()
