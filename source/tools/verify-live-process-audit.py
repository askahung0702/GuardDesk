"""Start one harmless Windows process; verify its real server audit records."""
import json
import os
import sqlite3
import subprocess
import time
from pathlib import Path


def main():
    root=Path(__file__).resolve().parents[1]
    config=json.loads((root/'runtime/agent/config.json').read_text(encoding='utf-8'))
    started=time.time()
    process=subprocess.Popen([str(Path(os.environ['SystemRoot'])/'System32/whoami.exe')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
    process.wait(timeout=5)
    deadline=time.monotonic()+35;found={};status={};usb={}
    while time.monotonic()<deadline:
        with sqlite3.connect(root/'runtime/control.sqlite3',timeout=10) as db:
            for kind,body,occurred,received in db.execute("SELECT kind,details,occurred,received FROM events WHERE device_id=? AND occurred>=? AND kind IN ('application.started','application.stopped')",(config['device_id'],started-2)):
                details=json.loads(body)
                try:pid=int(str(details.get('process_id','')),0)
                except ValueError:continue
                if pid==process.pid and Path(details.get('process','')).name.lower()=='whoami.exe':
                    found[kind]={'source':details.get('source'),'windows_event_id':details.get('windows_event_id'),'account_provided':bool(details.get('user')),'complete_process_path':bool(details.get('process')),'delivery_seconds':round(received-occurred,3),'command_line_collected':'command_line' in details or 'CommandLine' in details}
            row=db.execute('SELECT body FROM extended_status WHERE device_id=?',(config['device_id'],)).fetchone();status=json.loads(row[0]) if row else {}
            row=db.execute('SELECT body FROM native_usb_status WHERE device_id=?',(config['device_id'],)).fetchone();usb=json.loads(row[0]) if row else {}
        if len(found)==2 and status.get('status')=='configured':break
        time.sleep(.5)
    passed=len(found)==2 and all(row['source']=='windows_security' and row['account_provided'] and not row['command_line_collected'] for row in found.values()) and status.get('status')=='configured' and status.get('process_audit',{}).get('status')=='collecting' and usb.get('worker_version')=='0.4.3'
    report={'passed':passed,'real_process_started':True,'simulated_events':False,'test_program':'Windows whoami.exe','worker_version':usb.get('worker_version'),'collector_status':status.get('status'),'process_audit_status':status.get('process_audit',{}).get('status'),'configuration':status.get('process_audit_configuration'),'usb_mode':usb.get('usb_mode'),'events':found,'captured_at':time.time()}
    (root/'evidence/live-process-audit-0.4.3.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report));assert passed,'Real process audit verification failed'


if __name__=='__main__':main()
