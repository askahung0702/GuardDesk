"""Exercise final frozen native upload handler with owned offline config only."""
import hashlib,json,struct,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk.agent import Agent,private_write
from guarddesk import __version__


def main():
    exe=ROOT/'dist/GuardDesk/GuardDesk.exe'
    with tempfile.TemporaryDirectory(dir=ROOT/'runtime') as tmp:
        root=Path(tmp);watch=root/'documents';watch.mkdir();config=root/'runtime/agent/config.json'
        private_write(config,{'server':'http://127.0.0.1:1','token':'fixture-offline','device_id':'frozen-upload-fixture','watch':str(watch)})
        base={'type':'web_upload','upload_id':'frozen-flow','url':'https://fixture.invalid/upload?token=fixture-secret',
              'files':[{'path':str(watch/'owned.pdf')}],'method':'POST','browser':'edge','timestamp':time.time()*1000}
        messages=[{'type':'status','request_id':'capability'},
                  {**base,'phase':'started','event_id':'browser-frozen-start','request_id':'start'},
                  {**base,'phase':'response','event_id':'browser-frozen-response','status_code':201,'request_id':'response'}]
        payload=b''
        for m in messages:
            data=json.dumps(m).encode();payload+=struct.pack('<I',len(data))+data
        result=subprocess.run([str(exe),'browser-host','--config',str(config)],input=payload,capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        assert result.returncode==0,result.stderr.decode('utf-8',errors='replace')
        replies=[];output=result.stdout
        while output:
            size=struct.unpack('<I',output[:4])[0];replies.append(json.loads(output[4:4+size]));output=output[4+size:]
        assert len(replies)==3 and all(r['ok'] for r in replies),replies
        assert replies[0]['web_upload_audit'] is True and replies[0]['memory_upload_v1'] is True
        agent=Agent(config)
        try:
            with agent.db() as db:rows=[json.loads(r[0]) for r in db.execute('SELECT payload FROM outbox ORDER BY created')]
            assert [r['kind'] for r in rows]==['web.upload_started','web.upload_response']
            assert all(r['details']['source_path']==base['files'][0]['path'] and r['details']['application_success']=='unknown' for r in rows)
            assert 'fixture-secret' not in json.dumps(rows)
            assert agent.queue_status()['pending']==2
        finally:agent.close_collectors()
    report={'version':__version__,'passed':True,'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
            'checks':['Frozen native capability and upload module import','Three real framed Native Messaging requests and replies','Exact source path and HTTP 201 with application success unknown','Sensitive URL redaction and durable offline outbox'],
            'limitations':['Owned synthetic message stream, not installed browser registry or office Server','No protected installation or company Defender acceptance']}
    (ROOT/f'evidence/packaged-web-upload-{__version__}.json').write_text(json.dumps(report,indent=2),encoding='utf-8');print(json.dumps(report,indent=2))


if __name__=='__main__':main()
