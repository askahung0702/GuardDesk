"""Admin read-only versions of DEV's next-update actor; never dump config."""
import datetime,json,os
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]


def main():
    user=Path('C:/Users/dev/AppData/Local/GuardDeskPilotClient/runtime/agent/config.json')
    device=json.loads(user.read_text(encoding='utf-8-sig'))['device_id']
    private=Path(os.environ['ProgramData'])/'GuardDeskPilot/USBControl'/device
    result={'observed_at':datetime.datetime.now().astimezone().isoformat(),'company_changed':False}
    for label,path in (('broker',private/'broker-health.json'),('native',private/'native-health.json'),('updater_manifest',Path(os.environ['ProgramFiles'])/'GuardDeskPilot/Updater/_internal/agent-release.json')):
        try:
            with path.open('rb') as f:raw=f.read(2*1024*1024+1)
            if len(raw)>2*1024*1024:raise ValueError('Metadata exceeds bound')
            value=json.loads(raw)
            result[label]={k:value.get(k) for k in ('version','native_version','time','pid') if k in value}
        except (OSError,ValueError) as exc:result[label]={'error_type':type(exc).__name__,'winerror':getattr(exc,'winerror',None)}
    (ROOT/'evidence/maintenance/installed-update-actor-20261027.json').write_text(json.dumps(result,indent=2),encoding='utf-8')


if __name__=='__main__':main()
