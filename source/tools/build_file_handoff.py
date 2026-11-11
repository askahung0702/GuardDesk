"""Build the internal native handoff prototype; never installs or ships it.

Uses the same installed/pinned MSVC and SDK as build_document_trace.py.
Outputs stay under runtime/file-handoff-build, outside sealed release artifacts.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    base = Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'))
    vs = base / 'Microsoft Visual Studio/2019/BuildTools/VC/Tools/MSVC/14.29.30133'
    sdk = base / 'Windows Kits/10'
    version = '10.0.19041.0'
    compiler = vs / 'bin/Hostx64/x64/cl.exe'
    if not compiler.is_file():
        raise SystemExit('Pinned MSVC 14.29.30133 unavailable')
    work = ROOT / 'runtime/file-handoff-build'
    work.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env['PATH'] = str(compiler.parent) + os.pathsep + env['PATH']
    env['INCLUDE'] = ';'.join(map(str, [vs/'include', sdk/'Include'/version/'um', sdk/'Include'/version/'shared', sdk/'Include'/version/'ucrt']))
    env['LIB'] = ';'.join(map(str, [vs/'lib/x64', sdk/'Lib'/version/'um/x64', sdk/'Lib'/version/'ucrt/x64', work]))
    products = []
    for source, name, libraries, extension in [
        ('native/file_handoff.cpp', 'GuardDeskFileHandoff', ['ole32.lib', 'shell32.lib', 'uuid.lib'], '.dll'),
        ('native/tests/file_handoff_fixture.cpp', 'GuardDeskHandoffFixture', ['GuardDeskFileHandoff.lib', 'ole32.lib', 'uuid.lib'], '.dll'),
        ('native/tests/owned_ole_drop.cpp', 'GuardDeskOwnedOleDrop', ['ole32.lib', 'shell32.lib', 'uuid.lib', 'user32.lib'], '.exe'),
        ('native/tests/owned_file_picker.cpp', 'GuardDeskOwnedFilePicker', ['user32.lib'], '.exe'),
    ]:
        output = work / (name + extension)
        args = [str(compiler), '/nologo', '/std:c++17', '/EHsc', '/MT', '/O2', '/W4', '/WX', '/sdl', '/guard:cf', '/Brepro',
                '/DUNICODE', '/D_UNICODE', '/D_WIN32_WINNT=0x0602', *(['/LD'] if extension=='.dll' else []), str(ROOT/source),
                '/Fo'+str(work/(name+'.obj')), '/Fe'+str(output), '/link', '/DYNAMICBASE', '/NXCOMPAT', '/guard:cf', '/Brepro',
                '/IMPLIB:'+str(work/(name+'.lib')), *libraries]
        result = subprocess.run(args, env=env, cwd=work, capture_output=True)
        (work/(name+'.build.log')).write_bytes(result.stdout+result.stderr)
        if result.returncode:
            raise SystemExit((result.stdout+result.stderr).decode(errors='replace'))
        products.append({'source': source, 'source_sha256': hashlib.sha256((ROOT/source).read_bytes()).hexdigest(),
                         'dll': output.name, 'dll_sha256': hashlib.sha256(output.read_bytes()).hexdigest()})
    evidence = {'msvc': '14.29.30133', 'sdk': version, 'architecture': 'x64', 'abi': 1,
                'header_sha256': hashlib.sha256((ROOT/'native/file_handoff.h').read_bytes()).hexdigest(),
                'compiler_sha256': hashlib.sha256(compiler.read_bytes()).hexdigest(),
                'authenticode': 'not_signed_internal_prototype', 'installed': False,
                'chrome_edge_adapter': 'not_implemented', 'products': products}
    (work/'build.json').write_text(json.dumps(evidence, indent=2), encoding='utf-8')
    print(json.dumps(evidence))


if __name__ == '__main__':
    main()
