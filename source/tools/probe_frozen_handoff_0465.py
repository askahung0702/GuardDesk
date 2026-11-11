"""Compare actual sealed 0.4.64 and candidate 0.4.65 frozen journal readers."""
from pathlib import Path
import hashlib
import json
import tempfile
import types
import zipfile
from PyInstaller.archive.readers import CArchiveReader
from guarddesk import update_packages as packages

ROOT=Path(__file__).resolve().parents[1]


def functions(path):
    code=CArchiveReader(str(path)).open_embedded_archive('PYZ.pyz').extract('guarddesk.native_installer')
    constants={c.co_name:c for c in code.co_consts if isinstance(c,types.CodeType)}
    scope={'packages':packages,'json':json}
    scope['read_json']=types.FunctionType(constants['read_json'],scope,argdefs=(65536,))
    return types.FunctionType(constants['assert_quiescent'],scope,argdefs=(True,))


def main():
    candidate=ROOT/'dist/GuardDesk/GuardDesk.exe'
    old=ROOT/'dist/GuardDesk-0.4.64-windows-x64.zip'
    assert hashlib.sha256(old.read_bytes()).hexdigest()=='3c458a229988dc3d05bb6fd9dbc2125f42fe24a69a27622050a335f0d121be31'
    raw=(ROOT/'dist/transaction-native.json').read_bytes()
    with tempfile.TemporaryDirectory(prefix='frozen-handoff-',dir=ROOT/'runtime') as tmp:
        root=Path(tmp);previous=root/'OldGuardDesk.exe'
        with zipfile.ZipFile(old) as z:previous.write_bytes(z.read('GuardDesk/GuardDesk.exe'))
        old_check,new_check=functions(previous),functions(candidate)
        state=root/'owned';(state/'updates').mkdir(parents=True)
        p=state/'updates/transaction-native.json'
        fixture=json.loads(raw);fixture.update(phase='healthy',reported=True,version='0.4.64')
        p.write_text(json.dumps(fixture,ensure_ascii=False),encoding='utf-8')
        before=p.read_bytes()
        try:old_check(state)
        except ValueError:pass
        else:raise AssertionError('Actual sealed 0.4.64 must reproduce the size rejection')
        new_check(state);assert p.read_bytes()==before
        fixture['phase']='switching';p.write_text(json.dumps(fixture),encoding='utf-8')
        try:new_check(state)
        except OSError:pass
        else:raise AssertionError('New frozen code must still refuse in-progress switch')
        proof={'passed':True,'old_archive_sha256':hashlib.sha256(old.read_bytes()).hexdigest(),
               'candidate_exe_sha256':hashlib.sha256(candidate.read_bytes()).hexdigest(),
               'real_supplied_journal_bytes':len(raw),'owned_healthy_copy_bytes':len(before),
               'checks':['Actual archived 0.4.64 frozen read_json/assert_quiescent function code rejects completed large journal',
                         'Actual candidate 0.4.65 frozen function code accepts same owned copy without mutation',
                         'Actual candidate frozen function code still rejects switching phase'],
               'scope':'Frozen function execution in Python on owned copy only; no actual installed SYSTEM process/task/endpoint upgrade',
               'company_changed':False}
    (ROOT/'evidence/frozen-machine-handoff-0.4.65.json').write_text(json.dumps(proof,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(proof))


if __name__=='__main__':main()
