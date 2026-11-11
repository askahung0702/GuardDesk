"""Build the metadata collector with an installed official MSVC + Windows SDK.

No toolchain downloads, driver loading, test-signing, or system configuration.
"""
import hashlib,json,os,subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def main():
    vs=Path(os.environ.get('ProgramFiles(x86)',r'C:\Program Files (x86)'))/'Microsoft Visual Studio/2019/BuildTools/VC/Tools/MSVC/14.29.30133'
    sdk=Path(os.environ.get('ProgramFiles(x86)',r'C:\Program Files (x86)'))/'Windows Kits/10'
    compiler=vs/'bin/Hostx64/x64/cl.exe';version='10.0.19041.0'
    if not compiler.is_file():raise SystemExit('Required pinned MSVC 14.29.30133 unavailable')
    work=ROOT/'runtime/document-native-build';work.mkdir(parents=True,exist_ok=True)
    output=ROOT/'guarddesk/windows/native';output.mkdir(parents=True,exist_ok=True)
    source=ROOT/'native/document_trace.cpp';dll=output/'GuardDeskFileTrace.dll'
    env=os.environ.copy();env['PATH']=str(compiler.parent)+os.pathsep+env['PATH']
    env['INCLUDE']=';'.join(map(str,[vs/'include',sdk/'Include'/version/'um',sdk/'Include'/version/'shared',sdk/'Include'/version/'ucrt']))
    env['LIB']=';'.join(map(str,[vs/'lib/x64',sdk/'Lib'/version/'um/x64',sdk/'Lib'/version/'ucrt/x64']))
    args=[str(compiler),'/nologo','/std:c++17','/EHsc','/MT','/O2','/W4','/sdl','/guard:cf','/Brepro','/DUNICODE','/D_UNICODE','/D_WIN32_WINNT=0x0602','/LD',str(source),'/Fo'+str(work/'document_trace.obj'),'/Fe'+str(dll),'/link','/DYNAMICBASE','/NXCOMPAT','/guard:cf','/Brepro','/IMPLIB:'+str(work/'document_trace.lib')]
    result=subprocess.run(args,env=env,cwd=work,capture_output=True)
    (work/'build.log').write_bytes(result.stdout+result.stderr)
    if result.returncode:raise SystemExit((result.stdout+result.stderr).decode(errors='replace'))
    evidence={'msvc':'14.29.30133','sdk':version,'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'dll_sha256':hashlib.sha256(dll.read_bytes()).hexdigest(),'architecture':'x64','authenticode':'not_signed_internal_trial','driver_required':False,'compiler_sha256':hashlib.sha256(compiler.read_bytes()).hexdigest(),'build_exit_code':result.returncode}
    (output/'document-trace-build.json').write_text(json.dumps(evidence,indent=2),encoding='utf-8')
    print(json.dumps(evidence))


if __name__=='__main__':main()
