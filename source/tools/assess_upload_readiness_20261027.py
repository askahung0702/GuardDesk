"""Read-only local readiness: selected policy/handshake and our extension only.

Never read browser history, cookies, company files or credentials; no registry
or live SQLite writes, no cross-host database access or recursive profile scan.
"""
import datetime,json,os,sqlite3,sys,winreg
from contextlib import closing
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk.browser_host import extension_id,HOST_NAME


def main():
    local=Path(os.environ['LOCALAPPDATA']);runtime=local/'GuardDeskPilotClient/runtime/agent';eid=extension_id()
    result={'observed_at_taipei':datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(),'extension_id':eid,'registry':{},'profiles':[],'changes_performed':False}
    for browser,vendor in (('chrome','Google\\Chrome'),('edge','Microsoft\\Edge')):
        paths={'host':'Software\\'+vendor+'\\NativeMessagingHosts\\'+HOST_NAME,'force_policy':'Software\\Policies\\'+vendor+'\\ExtensionInstallForcelist'}
        for kind,keyname in paths.items():
            for hive,label in ((winreg.HKEY_CURRENT_USER,'HKCU'),(winreg.HKEY_LOCAL_MACHINE,'HKLM')):
                key=browser+'_'+kind+'_'+label
                try:
                    with winreg.OpenKey(hive,keyname,0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY) as handle:
                        if kind=='host':result['registry'][key]={'registered':True,'manifest_exists':Path(winreg.QueryValueEx(handle,'')[0]).is_file()}
                        else:
                            target=[]
                            for i in range(min(1000,winreg.QueryInfoKey(handle)[1])):
                                _,value,_=winreg.EnumValue(handle,i)
                                if isinstance(value,str) and value.split(';')[0]==eid:target.append(value)
                            result['registry'][key]={'our_policy':target}
                except FileNotFoundError:result['registry'][key]={'present':False}
                except OSError as e:result['registry'][key]={'error_type':type(e).__name__}
        base=local/('Google/Chrome/User Data' if browser=='chrome' else 'Microsoft/Edge/User Data')
        if base.is_dir():
            dirs=[p for p in base.iterdir() if p.is_dir() and (p.name=='Default' or p.name.startswith('Profile '))][:8]
            for p in dirs:
                ext=p/'Extensions'/eid;versions=[]
                if ext.is_dir():
                    for folder in list(ext.iterdir())[:8]:
                        manifest=folder/'manifest.json'
                        if manifest.is_file():
                            m=json.loads(manifest.read_text(encoding='utf-8'));versions.append(m.get('version'))
                result['profiles'].append({'browser':browser,'profile':p.name,'installed_manifest_versions':versions})
    config=runtime/'config.json'
    if config.is_file():
        c=json.loads(config.read_text(encoding='utf-8-sig'));result['server']=c.get('server')
        for name in ('runtime-health.json',):
            health=runtime/name
            if health.is_file():
                value=json.loads(health.read_text(encoding='utf-8'));result['main_health']={k:value.get(k) for k in ('version','time')}
        try:
            with closing(sqlite3.connect(config.with_suffix('.sqlite3').as_uri()+'?mode=ro',uri=True,timeout=1)) as db:
                for key in ('document_browser_sessions_v1','policy','feature_status'):
                    row=db.execute('SELECT value FROM state WHERE key=?',(key,)).fetchone();value=json.loads(row[0]) if row else None
                    if key=='policy':result['browser_audit_enabled']=value.get('body',{}).get('browser_audit') if isinstance(value,dict) else None
                    elif key=='feature_status' and isinstance(value,dict):result['collectors']={k:value.get(k) for k in ('document_upload','browser_native_host')}
                    else:result[key]=value
        except sqlite3.Error as e:result['state_read_error']=str(e)
    path=ROOT/'evidence/maintenance/upload-readiness-local-20261027.json'
    path.write_text(json.dumps(result,indent=2,ensure_ascii=False),encoding='utf-8');print(json.dumps(result,ensure_ascii=False))


if __name__=='__main__':main()
