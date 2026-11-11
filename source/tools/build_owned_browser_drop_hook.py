"""Pinned, unsigned owned-browser research DLL. No installation or registration."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    base = Path(r'C:\Program Files (x86)')
    vs = base/'Microsoft Visual Studio/2019/BuildTools/VC/Tools/MSVC/14.29.30133'
    sdk,version = base/'Windows Kits/10','10.0.19041.0'
    compiler = vs/'bin/Hostx64/x64/cl.exe'
    if not compiler.is_file():raise SystemExit('Pinned MSVC unavailable')
    work = ROOT/'runtime/owned-browser-drop-build'
    work.mkdir(exist_ok=True)
    env = os.environ.copy()
    env['PATH'] = str(compiler.parent)+os.pathsep+env['PATH']
    env['INCLUDE'] = ';'.join(map(str,[vs/'include',sdk/'Include'/version/'um',sdk/'Include'/version/'shared',sdk/'Include'/version/'ucrt',sdk/'Include'/version/'winrt']))
    env['LIB'] = ';'.join(map(str,[vs/'lib/x64',sdk/'Lib'/version/'um/x64',sdk/'Lib'/version/'ucrt/x64']))
    output = work/'GuardDeskOwnedBrowserDrop.dll'
    sources = ['native/tests/owned_browser_drop_hook.cpp','native/file_handoff.cpp']
    args = [str(compiler),'/nologo','/std:c++17','/EHsc','/MT','/O2','/W4','/WX','/sdl','/guard:cf','/Brepro',
            '/DUNICODE','/D_UNICODE','/D_WIN32_WINNT=0x0602','/LD',
            *[str(ROOT/name) for name in sources],'/Fo'+str(work)+'\\','/Fe'+str(output),'/link',
            '/DYNAMICBASE','/NXCOMPAT','/guard:cf','/Brepro','ole32.lib','oleacc.lib','oleaut32.lib','uuid.lib','shell32.lib','user32.lib']
    result = subprocess.run(args,env=env,cwd=work,capture_output=True)
    log = work/'build.log'
    log.write_bytes(result.stdout+result.stderr)
    if result.returncode:
        print((result.stdout+result.stderr).decode(errors='replace'))
        return result.returncode
    helper = work/'GuardDeskOwnedBrowserOleSource.exe'
    helper_args = [str(compiler),'/nologo','/std:c++17','/EHsc','/MT','/O2','/W4','/WX','/sdl','/guard:cf','/Brepro',
        '/DUNICODE','/D_UNICODE','/D_WIN32_WINNT=0x0602',str(ROOT/'native/tests/owned_browser_ole_source.cpp'),
        '/Fo'+str(work)+'\\','/Fe'+str(helper),'/link','/DYNAMICBASE','/NXCOMPAT','/guard:cf','/Brepro',
        'ole32.lib','oleaut32.lib','uuid.lib','shell32.lib','user32.lib']
    helper_result = subprocess.run(helper_args,env=env,cwd=work,capture_output=True)
    (work/'source-build.log').write_bytes(helper_result.stdout+helper_result.stderr)
    if helper_result.returncode:
        print((helper_result.stdout+helper_result.stderr).decode(errors='replace'))
        return helper_result.returncode
    budget = work/'GuardDeskOwnedBrowserBudget.exe'
    budget_args = [str(compiler),'/nologo','/std:c++17','/EHsc','/MT','/O2','/W4','/WX','/sdl','/guard:cf','/Brepro',
        '/DUNICODE','/D_UNICODE',str(ROOT/'native/tests/owned_browser_budget.cpp'),
        '/Fo'+str(work)+'\\','/Fe'+str(budget),'/link','/DYNAMICBASE','/NXCOMPAT','/guard:cf','/Brepro']
    budget_build = subprocess.run(budget_args,env=env,cwd=work,capture_output=True)
    (work/'budget-build.log').write_bytes(budget_build.stdout+budget_build.stderr)
    if budget_build.returncode:
        print((budget_build.stdout+budget_build.stderr).decode(errors='replace'))
        return budget_build.returncode
    budget_test = subprocess.run([str(budget)],capture_output=True,timeout=10)
    (work/'budget-test.json').write_bytes(budget_test.stdout)
    if budget_test.returncode:return budget_test.returncode
    report = {'architecture':'x64','msvc':'14.29.30133','sdk':version,'installed':False,
              'authenticode':'not_signed_research_only',
              'sources':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sources+[
                  'native/tests/owned_browser_drop_hook.h','native/tests/owned_browser_drop_hook_IA2_LICENSE.txt',
                  'native/tests/owned_browser_ole_source.cpp','native/tests/owned_ole_drop.cpp',
                  'native/file_handoff.h','native/tests/owned_browser_budget.h','native/tests/owned_browser_budget.cpp']},
              'dll_sha256':hashlib.sha256(output.read_bytes()).hexdigest(),
              'helper_sha256':hashlib.sha256(helper.read_bytes()).hexdigest(),
              'budget_test_sha256':hashlib.sha256(budget.read_bytes()).hexdigest(),
              'budget_source_sha256':{name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in
                  ['native/tests/owned_browser_budget.h','native/tests/owned_browser_budget.cpp']},
              'budget_test':json.loads(budget_test.stdout),
              'compiler_sha256':hashlib.sha256(compiler.read_bytes()).hexdigest()}
    (work/'build.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))
    return 0


if __name__ == '__main__':raise SystemExit(main())
