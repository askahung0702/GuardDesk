"""Actual frozen capacity/explicit-upgrade gates on owned data, no network or install."""
import argparse
import hashlib
import importlib.abc
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from PyInstaller.archive.readers import CArchiveReader

def main():
    p=argparse.ArgumentParser();p.add_argument('--product',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args()
    product=a.product.resolve(strict=True);report=a.report.absolute();workspace=Path(__file__).resolve().parents[3]
    if not product.is_relative_to(workspace/'runtime') or report.exists() or not report.is_relative_to(workspace/'runtime'):raise ValueError('New owned evidence required')
    archive=CArchiveReader(str(product/'GuardDesk.exe'));pyz=archive.open_embedded_archive(next(n for n in archive.toc if n.startswith('PYZ')))
    if any(n=='guarddesk' or n.startswith('guarddesk.') for n in sys.modules):raise ValueError('Fresh interpreter required')
    required={'guarddesk.endpoint_setup','guarddesk.update_storage','guarddesk.update_client','guarddesk.endpoint_package'}
    if not required<=pyz.toc.keys():raise ValueError('Installer module missing from actual EXE: '+str(required-pyz.toc.keys()))
    class Frozen(importlib.abc.MetaPathFinder,importlib.abc.Loader):
        def find_spec(self,name,path=None,target=None):
            if name in ('guarddesk','tools') or name.startswith(('guarddesk.','tools.')):
                if name not in pyz.toc:raise ModuleNotFoundError('Missing frozen module '+name)
                return importlib.util.spec_from_loader(name,self,is_package=pyz.toc[name][0] in (1,3))
        def create_module(self,spec):return None
        def exec_module(self,module):
            module.__file__=str(product/'_internal'/module.__name__.replace('.','/'))+'.py'
            code=pyz.extract(module.__name__)
            if code is not None:exec(code,module.__dict__)
    sys.meta_path.insert(0,Frozen())
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tests'))
    suite=unittest.TestSuite()
    for name in ('test_update_storage_scan','test_explicit_service_upgrade','test_native_capacity_repair','test_endpoint_entry_cmd'):
        spec=importlib.util.spec_from_file_location(name,Path(__file__).resolve().parents[1]/'tests'/(name+'.py'))
        fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(fixture))
    with report.with_suffix('.log').open('x',encoding='utf-8') as log:
        result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
    value={'passed':result.wasSuccessful() and not result.skipped,'tests':result.testsRun,'errors':len(result.errors),'failures':len(result.failures),
           'runtime_sha256':hashlib.sha256((product/'GuardDesk.exe').read_bytes()).hexdigest(),'required_modules':sorted(required),
           'source_fallback_allowed':False,'center_started':False,'installed_Agent_changed':False,'SYSTEM_task_created':False}
    report.write_text(json.dumps(value,indent=2),encoding='utf-8');print(json.dumps(value));return int(not value['passed'])

if __name__=='__main__':raise SystemExit(main())
