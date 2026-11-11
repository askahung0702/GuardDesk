"""Actual ServiceWindows adapter with only SCM/schtasks side effects replaced."""
import argparse,importlib.abc,importlib.util,json,sys,tempfile
from pathlib import Path
from unittest.mock import Mock,patch

def cases():
    from guarddesk import remote_service as rs,native_installer as ni
    exe=Path(r'C:\Program Files\GuardDeskPilot\USBControl\GuardDesk.exe')
    config=Path(r'C:\ProgramData\GuardDeskPilot\USBControl')/('a'*24)/'config.json'
    name='GuardDesk-USBControl-'+'a'*24
    raw=ni.task_body(exe,config,'native');checks=[]
    for case in ('legacy_valid','legacy_foreign','legacy_query_denied','legacy_delete_failed','fresh_service','existing_service','foreign_service'):
        service=Mock(spec=rs.Service);service.query.return_value=None
        expected=rs.description(exe,config);events=[]
        if case=='existing_service':service.query.return_value=expected
        if case=='foreign_service':service.query.return_value={**expected,'device_id':'b'*24}
        def command(self,args):
            events.append(args)
            if args==['/Query','/FO','CSV','/NH']:
                return (('"\\'+name+'","N/A","Ready"\r\n').encode('ascii') if case.startswith('legacy_') else b'')
            if args==['/Query','/TN',name,'/XML']:
                if case=='legacy_query_denied':raise PermissionError('owned denied query')
                return ni.task_body(exe.with_name('foreign.exe'),config,'native') if case=='legacy_foreign' else raw
            if args==['/Delete','/TN',name,'/F']:
                if case=='legacy_delete_failed':raise OSError('owned failed deletion')
                return b''
            raise AssertionError('Unexpected OS command')
        with patch.object(rs,'Service',return_value=service),patch.object(ni.Windows,'command',command):
            ops=rs.platform();ops.verify(raw,exe,config,'native')
            if case in ('legacy_foreign','legacy_query_denied','legacy_delete_failed','foreign_service'):
                try:ops.register(name,expected,Path('unused'))
                except OSError:pass
                else:raise AssertionError('Invalid migration accepted: '+case)
                service.create.assert_not_called()
                if case!='legacy_delete_failed':assert not any(a[0]=='/Delete' for a in events)
            else:
                ops.register(name,expected,Path('unused'))
                if case=='existing_service':service.create.assert_not_called()
                else:service.create.assert_called_once_with(expected)
                if case=='legacy_valid':assert events[-1]==['/Delete','/TN',name,'/F']
        checks.append(case)
    return checks

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--build',type=Path);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();report={'passed':False,'installed':False,'OS_mutations':False,'SCM_tested':False}
    if args.build:
        from PyInstaller.archive.readers import CArchiveReader
        import hashlib
        build=args.build.resolve();receipt=json.loads((build/'receipt.json').read_text())
        exe=build/'product/GuardDesk/GuardDeskInstaller.exe'
        assert hashlib.sha256(exe.read_bytes()).hexdigest()==receipt['files']['GuardDeskInstaller.exe']['sha256']
        archive=CArchiveReader(str(exe));pyz=archive.open_embedded_archive(next(n for n in archive.toc if n.startswith('PYZ')))
        class Frozen(importlib.abc.MetaPathFinder,importlib.abc.Loader):
            def find_spec(self,fullname,path=None,target=None):
                if fullname=='guarddesk' or fullname.startswith('guarddesk.'):
                    if fullname not in pyz.toc:raise ModuleNotFoundError(fullname)
                    return importlib.util.spec_from_loader(fullname,self,is_package=fullname=='guarddesk')
            def create_module(self,spec):return None
            def exec_module(self,module):
                module.__file__=str(exe.parent/'_internal'/module.__name__.replace('.','/'))+'.py'
                exec(pyz.extract(module.__name__),module.__dict__)
        assert not any(n=='guarddesk' or n.startswith('guarddesk.') for n in sys.modules)
        sys.meta_path.insert(0,Frozen());report['artifact']=str(exe);report['sha256']=hashlib.sha256(exe.read_bytes()).hexdigest()
    try:report['checks']=cases();report['passed']=True
    except Exception as exc:report['error']={'type':type(exc).__name__,'message':str(exc)}
    with args.output.open('x',encoding='utf-8') as f:json.dump(report,f,indent=2)
    print(json.dumps(report));raise SystemExit(not report['passed'])
if __name__=='__main__':main()
