"""Real sealed 66 transaction and exact candidate runtime; owned OS substitutes."""
import hashlib,json,os,shutil,subprocess,sys,tempfile,time,types,zipfile
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk import update_packages as packages
from guarddesk.update_preflight import candidate_size
from tools.reproduce_native_budget_failure import sparse


def load(exe):
    module=types.ModuleType('guarddesk.owned_frozen_update_client');module.__package__='guarddesk'
    code=CArchiveReader(str(exe)).open_embedded_archive('PYZ.pyz').extract('guarddesk.update_client')
    exec(code,module.__dict__);return module


def main():
    target=ROOT/'evidence/update-boundary-frozen-0.4.69.json';assert not target.exists()
    app=ROOT/'dist/GuardDesk';candidate=app/'GuardDesk.exe'
    with tempfile.TemporaryDirectory(prefix='update-boundary-',dir=ROOT/'runtime') as tmp:
        root=Path(tmp);old=root/'sealed66.exe'
        with zipfile.ZipFile(ROOT/'dist/GuardDesk-0.4.66-windows-x64.zip') as archive:old.write_bytes(archive.read('GuardDesk/GuardDesk.exe'))
        assert packages.file_hash(old)=='80f60d3cd2151dac648ac85cb9a794f4adc7045bbdb4cccfd1e8c5cdfa760d7f'
        expected=json.loads((app/'_internal/agent-release.json').read_text())['files']
        expected={**expected,'_internal/agent-release.json':packages.file_hash(app/'_internal/agent-release.json')}
        archive=root/'candidate.zip'
        with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as out:
            for name in sorted(expected):
                with (app/name).open('rb') as src,out.open(name,'w') as dst:shutil.copyfileobj(src,dst,65536)
        size=candidate_size(app);assert size['compressed_bytes']==archive.stat().st_size
        manifest={'format':1,'version':'0.4.69','architecture':'windows-x64','sha256':packages.file_hash(archive),'bytes':archive.stat().st_size,'files':expected}
        private=packages.signer(root);key=packages.public_key(private)
        from types import SimpleNamespace
        from guarddesk.update_client import probe
        old66=load(old);new69=load(candidate)
        scenarios=[]
        for label,module,retained in [('old66_retained_cache',old66,True),('old66_after_owned_cache_archive',old66,False),('new69_retained_cache',new69,True),('new69_lost_completion_ACK',new69,True)]:
            base=root/label;base.mkdir();program=base/'program';program.mkdir();data=base/'data';data.mkdir();cfg=data/'config.json';cfg.write_text('owned-identity')
            sparse(program/'owned-measured-program.bin',383895008)
            updates=data/'updates';updates.mkdir()
            if retained:sparse(updates/'owned-ended-cache.bin',55155846)
            reports=[];agent=SimpleNamespace(config_path=cfg,config={'device_id':'a'*24,'update_key':key},call=lambda path,body:reports.append(body) or {'ok':True})
            class Adapter:
                value='0.4.66';stops=0
                def current(self):return self.value
                def stage(self,job):return program/('USBControl.stage-'+job['id'])
                def validate_stage(self,path):pass  # Owned standard-user ACL, not SYSTEM acceptance.
                def budget(self,incoming):module.storage_budget([program,updates],incoming)
                def probe(self,path):return probe(path)  # Execute exact verified candidate CLI.
                def stop(self):self.stops+=1
                def switch(self,state,write):self.value=state['target'];state['phase']='switching';write(state)
                def start(self,state,rollback):pass
                def health(self,version,started,timeout):return self.value==version
                def rollback(self,state):self.value=state['old_version']
                def cleanup(self,state):pass
            adapter=Adapter();tx=module.Transaction(agent,'native',adapter)
            now=time.time();job={'id':'b'*32,'device_id':'a'*24,'release_id':manifest['sha256'],'created':now,'not_before':now,'expires':now+86400,'allow_downgrade':0,'release':packages.sign(private,manifest)}
            module.download=lambda agent,job,manifest,path:shutil.copyfile(archive,path)
            normal_call=agent.call
            if label=='new69_lost_completion_ACK':
                def lost_ack(path,body):
                    if body.get('state')=='healthy':raise ConnectionError('owned lost ACK')
                    return normal_call(path,body)
                agent.call=lost_ack
            caught=None
            try:tx.apply(packages.sign(private,job))
            except OSError as exc:caught=str(exc)
            if label=='new69_lost_completion_ACK':
                assert caught and not json.loads(tx.journal.read_text(encoding='utf-8'))['reported']
                agent.call=normal_call;tx.recover();caught=None
                receipt=tx.root/job['id']/'cache-receipt.json';assert receipt.is_file();before=receipt.stat().st_mtime_ns
                tx.recover();assert receipt.stat().st_mtime_ns==before
            state=json.loads(tx.journal.read_text(encoding='utf-8'))
            if label=='old66_retained_cache':assert caught and '512 MiB' in caught and adapter.stops==0 and not adapter.stage(job).exists()
            else:assert caught is None and state['phase']=='healthy' and adapter.stops==1 and probe(adapter.stage(job))=='0.4.69'
            assert cfg.read_text()=='owned-identity'
            scenarios.append({'name':label,'phase':state['phase'],'stops':adapter.stops,'candidate_probe_real':label!='old66_retained_cache','error':caught,'identity_preserved':True})
        # Real frozen 69 capacity module, distinct from single-package limits.
        archive69=CArchiveReader(str(candidate)).open_embedded_archive('PYZ.pyz')
        capacity=types.ModuleType('guarddesk.owned_capacity');capacity.__package__='guarddesk'
        exec(archive69.extract('guarddesk.update_storage'),capacity.__dict__)
        sparse(root/'owned-next-update.bin',580374017)
        value=capacity.budget([root/'new69_retained_cache/program',root/'new69_retained_cache/data/updates'],size['incoming_bytes'])
        assert value['projected_bytes']<value['limit_bytes']
        proof={'passed':True,'version':'0.4.69','exe_sha256':packages.file_hash(candidate),'old_exe_sha256':packages.file_hash(old),
            'candidate_runtime':{**size,'sha256':manifest['sha256']},'scenarios':scenarios,'next_refresh_working_set':value,
            'company_changed':False,'SYSTEM_tasks_ACL_switch_and_health':'simulated owned adapter; candidate CLI, signed manifests, extraction and hashes real',
            'scope':'Frozen 66 Transaction/storage_budget and exact frozen 69 candidate, plus frozen 69 transaction; download uses owned copy instead of transport',
            'field_acceptance':False}
        target.write_text(json.dumps(proof,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps(proof,ensure_ascii=False))


if __name__=='__main__':main()
