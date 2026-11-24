"""Actual new/111 PYZ service adapters with owned Win32 configuration buffers.

Never creates, starts, stops or changes a real service or management center.
"""
import argparse,ctypes,hashlib,json,subprocess,tempfile,types,zipfile
from contextlib import nullcontext
from pathlib import Path
from PyInstaller.archive.readers import CArchiveReader

DID='a'*24
BINARY='"C:\\Program Files\\GuardDeskPilot\\USBControl\\_internal\\GuardDeskService.exe" --device-id '+DID

class OwnedAPI:
    def __init__(self,module,start):self.module=module;self.start=start;self.mutations=[];self.buffers=[];self.account='LocalSystem';self.binary=BINARY
    def QueryServiceConfigW(self,handle,data,size,needed):
        ctypes.cast(needed,ctypes.POINTER(ctypes.c_ulong))[0]=4096
        if data is None:return False
        cfg=ctypes.cast(data,ctypes.POINTER(self.module.Config)).contents
        cfg.type=0x10;cfg.start=self.start;cfg.error=1
        self.buffers=[ctypes.create_unicode_buffer(self.account),ctypes.create_unicode_buffer(self.binary)]
        cfg.account=ctypes.cast(self.buffers[0],ctypes.c_wchar_p);cfg.binary=ctypes.cast(self.buffers[1],ctypes.c_wchar_p)
        cfg.dependencies=None;cfg.group=None;return True
    def QueryServiceStatusEx(self,handle,kind,data,size,needed):
        value=ctypes.cast(data,ctypes.POINTER(self.module.Status)).contents;value.state=1;return True
    def StartServiceW(self,*args):self.mutations.append('start');return True
    def ControlService(self,*args):self.mutations.append('stop');return True
    def DeleteService(self,*args):self.mutations.append('delete');return True
    def ChangeServiceConfigW(self,handle,kind,start,error,*rest):
        assert handle==1 and kind==0xffffffff and start==4 and error==0xffffffff and rest==(None,)*7
        self.mutations.append('disable');self.start=4;return True

def fixture(module,start):
    service=module.Service.__new__(module.Service);service.api=OwnedAPI(module,start)
    service.opened=lambda *args,**kwargs:nullcontext(1)
    return service

def rejected(call):
    try:call()
    except PermissionError:return
    raise AssertionError('Unsafe configuration accepted')

def cases(new,legacy=None):
    expected={'kind':'remote-service-v1','device_id':DID,'binary':BINARY};checks=[]
    auto=fixture(new,2);assert auto.read(1)==expected;checks.append('new_auto_contract_unchanged')
    disabled=fixture(new,4);assert disabled.query()==expected
    rejected(lambda:disabled.action(expected,'start'));assert not disabled.api.mutations
    checks.append('new_disabled_query_visible_start_refused')
    disabled.action(expected,'stop');assert not disabled.api.mutations
    disabled.action(expected,'delete');assert disabled.api.mutations==['delete']
    checks.append('new_disabled_stop_delete_available_without_reset')
    retiring=fixture(new,4);retiring.retire_self(expected);assert retiring.api.mutations==['delete']
    checks.append('new_disabled_final_ack_retirement_preserved')
    for start in (0,1,3):rejected(lambda:fixture(new,start).query())
    checks.append('unknown_start_modes_refused')
    for field,value in [('account','owned-user'),('binary','C:\\owned\\foreign.exe')]:
        foreign=fixture(new,4);setattr(foreign.api,field,value);rejected(foreign.query)
    checks.append('disabled_does_not_relax_account_or_binary')
    fenced=fixture(new,2);fenced.disable_for_recovery(expected)
    assert fenced.api.start==4 and fenced.api.mutations==['disable']
    rejected(lambda:fenced.action(expected,'start'));assert fenced.api.mutations==['disable']
    checks.append('immediate_worker_fence_changes_only_start_type_and_blocks_start')
    foreign=fixture(new,2)
    rejected(lambda:foreign.disable_for_recovery({**expected,'device_id':'b'*24}));assert not foreign.api.mutations
    checks.append('immediate_fence_refuses_foreign_identity_before_mutation')
    if legacy is not None:
        old_auto=fixture(legacy,2);assert old_auto.read(1)==expected
        checks.append('actual111_auto_still_allowed')
        for action in ('start','stop','delete'):
            old=fixture(legacy,4);rejected(lambda:old.action(expected,action));assert not old.api.mutations
            checks.append('actual111_disabled_'+action+'_refused_before_mutation')
    return checks

def frozen_module(exe,name):
    archive=CArchiveReader(str(exe));pyz=archive.open_embedded_archive(next(n for n in archive.toc if n.startswith('PYZ')))
    code=pyz.extract('guarddesk.remote_service');module=types.ModuleType(name);module.__package__='guarddesk';exec(code,module.__dict__);return module

from tools.offline_build_guard import guarded_main

@guarded_main
def main():
    parser=argparse.ArgumentParser();parser.add_argument('--product',type=Path,required=True)
    parser.add_argument('--baseline-package',type=Path,required=True);parser.add_argument('--baseline-sha256',required=True)
    parser.add_argument('--report',type=Path,required=True);args=parser.parse_args()
    report=args.report.resolve();product=args.product.resolve(strict=True)
    workspace=Path(__file__).resolve().parents[3]
    if report.exists() or not report.is_relative_to(workspace/'runtime') or not product.is_relative_to(workspace/'runtime'):
        raise ValueError('Owned runtime evidence required')
    def digest(path):
        with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
    assert digest(args.baseline_package)==args.baseline_sha256
    result={'passed':False,'SCM_tested':False,'SYSTEM_tested':False,'local_center_started':False,'installed_Agent_changed':False}
    try:
        new=frozen_module(product/'GuardDesk.exe','owned_new_service')
        with tempfile.TemporaryDirectory(prefix='old111-owned-',dir=report.parent) as folder:
            old_exe=Path(folder)/'GuardDesk.exe'
            with zipfile.ZipFile(args.baseline_package) as archive:
                member=archive.getinfo('GuardDesk/GuardDesk.exe');assert member.file_size<64*1024*1024
                old_exe.write_bytes(archive.read(member))
            legacy=frozen_module(old_exe,'owned_actual111_service')
            result['cases']=cases(new,legacy);result['old111_exe_sha256']=digest(old_exe)
        service=product/'_internal/GuardDeskService.exe'
        for command in ('--component-info','--recovery-help'):
            value=subprocess.run([str(service),command],capture_output=True,check=True,timeout=10)
            body=json.loads(value.stdout)
            if command=='--component-info':assert body['recovery_maintenance']==1 and body['rollback_guard']=='service-disabled-v1'
            else:assert body['admin_required'] and body['stopped_required_for_reset'] and not body['automatic_start']
        result.update(passed=True,actual_service_sha256=digest(service),new_exe_sha256=digest(product/'GuardDesk.exe'),
                      baseline_package_sha256=args.baseline_sha256,
                      guard_limit='Owned API buffers demonstrate actual111 rejects Disabled; actual SCM disable/readback and cross-account operation remain external acceptance.')
    except Exception as error:result['failure']={'type':type(error).__name__,'message':str(error)}
    report.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps(result));raise SystemExit(not result['passed'])

if __name__=='__main__':main()
