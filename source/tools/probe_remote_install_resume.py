"""Real installer PYZ and staging; only privileged installation/readiness mocked.

Starts from a matching incomplete identity whose old supervisor pipe is absent.
Never enrolls, changes an installed Agent, launches a service or uses the network.
"""
import argparse
import base64
import hashlib
import importlib.abc
import importlib.util
import json
from pathlib import Path
import shutil
import sys
from unittest.mock import patch
from PyInstaller.archive.readers import CArchiveReader


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--product',type=Path,required=True);parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args();runtime=Path(__file__).resolve().parents[2]
    product=args.product.resolve(strict=True);output=args.report.absolute()
    if product.name!='GuardDesk' or product.parent.name!='product' or product.parent.parent.parent!=runtime:raise ValueError('Owned product required')
    if not output.resolve().is_relative_to(runtime) or output.exists():raise ValueError('New owned report required')
    if any(n=='guarddesk' or n.startswith('guarddesk.') for n in sys.modules):raise ValueError('Fresh interpreter required')
    pyz=CArchiveReader(str(product/'GuardDeskInstaller.exe')).open_embedded_archive('PYZ.pyz')
    class Frozen(importlib.abc.MetaPathFinder,importlib.abc.Loader):
        def find_spec(self,name,path=None,target=None):
            if name=='guarddesk' or name.startswith('guarddesk.'):
                if name not in pyz.toc:raise ModuleNotFoundError('Absent frozen module '+name,name=name)
                return importlib.util.spec_from_loader(name,self,is_package=name=='guarddesk')
        def create_module(self,spec):return None
        def exec_module(self,module):
            module.__file__=str(product/'_internal'/module.__name__.replace('.','/'))+'.py'
            exec(pyz.extract(module.__name__),module.__dict__)
    sys.meta_path.insert(0,Frozen())
    from guarddesk import endpoint_setup,remote_trial,__version__,usb_install
    from guarddesk.remote_endpoint_state import RemoteEndpointState
    assert remote_trial.enabled()
    report={'passed':False,'installer_sha256':digest(product/'GuardDeskInstaller.exe'),'source_fallback_allowed':False,
        'network_requests':False,'installed_Agent_changed':False,'privileged_native_install_mocked':True,
        'session_ready_effect_mocked':True,'deployable':False,'checks':[]}
    root=output.with_suffix('.fixture');root.mkdir()
    package=root/'package';package.mkdir();shutil.copytree(product,package/'GuardDesk')
    hashes={p.relative_to(product).as_posix():digest(p) for p in product.rglob('*') if p.is_file()}
    (package/'endpoint-files.json').write_text(json.dumps({'version':__version__,'files':hashes}))
    ca=b'OWNED PUBLIC TEST CA';(package/'GuardDesk-CA.pem').write_bytes(ca)
    (package/'endpoint-connection.json').write_text(json.dumps({'version':1,'server':'https://owned.invalid','ca':'GuardDesk-CA.pem','ca_sha256':hashlib.sha256(ca).hexdigest()}))
    key=base64.b64encode(b'x'*32).decode();(package/'update-trust.json').write_text(json.dumps({'format':1,'public_key':key}))
    did='a'*24;checks=report['checks'];counter=0
    def fixture(label,version='0.4.88'):
        user=root/label;config=user/'runtime/agent/config.json';config.parent.mkdir(parents=True)
        (config.parent/'GuardDesk-CA.pem').write_bytes(ca)
        value={'server':'https://owned.invalid','device_id':did,'token':'OWNED_PRIVATE_TOKEN','ca':str(config.parent/'GuardDesk-CA.pem'),
            'install_profile':remote_trial.PROFILE,'update_key':key}
        config.write_text(json.dumps(value))
        state={'product':'GuardDeskEndpoint','config':str(config),'version':version,'phase':'native_installed','last_result':'incomplete_retry_same_installer'}
        (user/'endpoint-install.json').write_text(json.dumps(state))
        machine={'device_id':did,'server':value['server'],'version':version,'ca_sha256':hashlib.sha256(ca).hexdigest(),
            'install_profile':remote_trial.PROFILE,'scope':'machine','status':'supervisor_unavailable'}
        return user,config,state,machine
    def exercise(label,old_version,completed_upgrade=False):
        nonlocal counter
        user,config,state,machine=fixture(label,old_version)
        if completed_upgrade:
            state.update(phase='ready',last_result='completed');(user/'endpoint-install.json').write_text(json.dumps(state));machine['status']='online'
        original=json.loads(config.read_text());agent=RemoteEndpointState(config)
        with agent.db() as db:db.execute("INSERT INTO state VALUES ('owned_cursor','KEEP')")
        native=[]
        def privileged(path,*args,**kwargs):
            actual=json.loads(Path(path).read_text())
            assert actual['device_id']==original['device_id'] and actual['token']==original['token']
            native.append(True);machine.update(version=__version__,status='online')
        def ready(actual_did,version):return bool(native) and actual_did==did and version==__version__
        # _install, staging, existing config/state DB and completion are real.
        with patch('guarddesk.machine_agent_session.discover',side_effect=lambda:dict(machine)),patch.object(endpoint_setup,'client_root',return_value=user),patch('guarddesk.desktop_agent.client_root',return_value=user),patch('guarddesk.windows_privilege.is_admin',return_value=False),patch.object(endpoint_setup,'enroll',side_effect=AssertionError('MUST NOT ENROLL')) as enroll,patch.object(usb_install,'install',side_effect=privileged),patch.object(endpoint_setup,'session_ready',side_effect=ready):
            result=endpoint_setup.install(package/'endpoint-connection.json',upgrade_existing=completed_upgrade)
        assert result['status']=='installed' and len(native)==1;enroll.assert_not_called()
        actual=json.loads(config.read_text());assert actual['device_id']==did and actual['token']==original['token']
        finished=json.loads((user/'endpoint-install.json').read_text());assert finished['phase']=='ready' and finished['last_result']=='completed'
        assert json.loads((config.parent/'installation-diagnostic.json').read_text())['code']=='completed'
        with RemoteEndpointState(config).db() as db:assert db.execute("SELECT value FROM state WHERE key='owned_cursor'").fetchone()[0]=='KEEP'
        counter+=1
    try:
        exercise('newer-package','0.4.88');checks.append('offline_pending_088_full_resume_to_target_without_enrollment_or_identity_reset')
        exercise('same-version',__version__);checks.append('offline_pending_same_version_retries_same_installation')
        exercise('live-completed-upgrade','0.4.91',True);checks.append('explicit_live_completed_091_upgrade_retains_identity_and_database')
        if tuple(map(int,__version__.split('.')))>(0,4,92):
            exercise('live-completed-092-upgrade','0.4.92',True);checks.append('explicit_live_completed_092_upgrade_retains_identity_and_database')
        for reason in ('completed','other_identity','wrong_ca','missing_marker','downgrade'):
            user,config,state,machine=fixture('reject-'+reason)
            if reason=='completed':state['last_result']='completed'
            if reason=='other_identity':machine['device_id']='b'*24
            if reason=='wrong_ca':machine['ca_sha256']='b'*64
            if reason=='downgrade':machine['version']='99.0.0'
            marker=user/'endpoint-install.json'
            if reason=='missing_marker':marker.unlink()
            else:marker.write_text(json.dumps(state))
            before=config.read_bytes()
            with patch('guarddesk.machine_agent_session.discover',return_value=machine),patch.object(endpoint_setup,'client_root',return_value=user),patch.object(endpoint_setup,'_install',side_effect=AssertionError('MUST NOT INSTALL')) as install,patch.object(endpoint_setup,'enroll',side_effect=AssertionError('MUST NOT ENROLL')) as enroll:
                try:endpoint_setup.install(package/'endpoint-connection.json')
                except (OSError,ValueError):pass
                else:raise AssertionError('Unsafe offline repair accepted: '+reason)
            install.assert_not_called();enroll.assert_not_called();assert config.read_bytes()==before
            checks.append('offline_rejects_'+reason)
        for reason in ('offline_completed','other_identity','wrong_ca','missing_marker','downgrade','missing_user_config'):
            user,config,state,machine=fixture('explicit-reject-'+reason,'0.4.91')
            state.update(phase='ready',last_result='completed');machine['status']='online'
            if reason=='offline_completed':machine['status']='supervisor_unavailable'
            if reason=='other_identity':machine['device_id']='b'*24
            if reason=='wrong_ca':machine['ca_sha256']='b'*64
            if reason=='downgrade':machine['version']='99.0.0'
            marker=user/'endpoint-install.json';marker.write_text(json.dumps(state))
            if reason=='missing_marker':marker.unlink()
            if reason=='missing_user_config':config.unlink()
            with patch('guarddesk.machine_agent_session.discover',return_value=machine),patch.object(endpoint_setup,'client_root',return_value=user),patch.object(endpoint_setup,'_install',side_effect=AssertionError('MUST NOT INSTALL')) as install,patch.object(endpoint_setup,'enroll',side_effect=AssertionError('MUST NOT ENROLL')) as enroll:
                try:endpoint_setup.install(package/'endpoint-connection.json',upgrade_existing=True)
                except (OSError,ValueError):pass
                else:raise AssertionError('Unsafe explicit upgrade accepted: '+reason)
            install.assert_not_called();enroll.assert_not_called();checks.append('explicit_upgrade_rejects_'+reason)
        report.update(passed=True,real_staging_and_completion_cases=counter)
    except Exception as exc:
        report.update(error_type=type(exc).__name__,error_message=str(exc)[:300])
    with output.open('x',encoding='utf-8') as stream:json.dump(report,stream,indent=2)
    print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
