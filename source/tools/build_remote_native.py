"""Build the isolated native components and run the exact owned test inventory.

No product launch, desktop, input, tasks, policy or installed Agent access.
Logs and exact source/artifact receipts are numbered; old failures stay intact.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

SOURCE=Path(__file__).resolve().parents[1]
WORKSPACE=SOURCE.parents[1]
NATIVE=SOURCE/'native/remote'
BUILD=WORKSPACE/'runtime/remote-next-m3-build'
BIN=Path('C:/Program Files (x86)/Microsoft Visual Studio/2019/BuildTools/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin')
TESTS={'remote_display_geometry_selftest':('GuardDeskRemoteDisplayGeometryProbe.exe',),
    'remote_owned_pointer_flow_selftest':('GuardDeskRemotePointerFlowProbe.exe',),
    'remote_owned_native_broker_pump_selftest':('GuardDeskRemoteBrokerPumpProbe.exe',),
    'remote_owned_media_runtime_selftest':('GuardDeskRemoteMediaRuntimeProbe.exe',),
    'remote_kernel_trust_selftest':('GuardDeskRemoteKernelTrustProbe.exe',),
    'remote_no_desktop_selftest':('GuardDeskRemoteFoundationProbe.exe','--self-test'),
    'remote_owned_ipc_peer_selftest':('GuardDeskRemoteIpcPeerProbe.exe','--self-test'),
    'remote_control_wire_selftest':('GuardDeskRemoteControlWireProbe.exe',),
    'remote_owned_native_channel_selftest':('GuardDeskRemoteChannelProbe.exe','--self-test'),
    'remote_owned_channel_quarantine_selftest':('GuardDeskRemoteChannelProbe.exe','--owned-quarantine'),
    'remote_owned_session_selftest':('GuardDeskRemoteSessionProbe.exe',),
    'remote_owned_hidden_viewer_selftest':('GuardDeskRemoteViewerProbe.exe',),
    'remote_worker_unbound_entry_rejected':('GuardDeskRemoteWorker.exe','--unbound-test'),
    'remote_media_wire_selftest':('GuardDeskRemoteMediaWireProbe.exe',),
    'remote_broker_invalid_prelaunch_selftest':('GuardDeskRemoteBrokerProbe.exe',)}


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def sources():
    return {path.relative_to(SOURCE).as_posix():digest(path) for path in sorted(NATIVE.iterdir())
        if path.is_file() and (path.suffix in ('.cpp','.hpp') or path.name=='CMakeLists.txt')}


def main():
    if sys.argv[1:]!=['--owned-tests']:raise SystemExit('Use --owned-tests; no desktop or installed product is tested')
    before=sources();number=1
    while (WORKSPACE/f'runtime/remote-m2-native-build-{number:03}.log').exists():number+=1
    log=WORKSPACE/f'runtime/remote-m2-native-build-{number:03}.log'
    receipt={'format':1,'sources':before,'source_stable':False,'stages':[],'passed':False,
        'desktop_capture':False,'OS_input':False,'SYSTEM_boundary':False,'product_installed':False,'deployable':False}
    try:
        with log.open('x',encoding='utf-8') as output:
            for label,arguments in (
                ('configure',[str(BIN/'cmake.exe'),'-S',str(NATIVE),'-B',str(BUILD),'-G','Visual Studio 16 2019','-A','x64']),
                ('build',[str(BIN/'cmake.exe'),'--build',str(BUILD),'--config','Release','--parallel','2'])):
                result=subprocess.run(arguments,stdout=output,stderr=subprocess.STDOUT,timeout=180)
                receipt['stages'].append({'stage':label,'exit':result.returncode})
                if result.returncode:raise RuntimeError('Owned native build failed; no old executable was run')
            listing=subprocess.run([str(BIN/'ctest.exe'),'--test-dir',str(BUILD),'-C','Release','--show-only=json-v1'],capture_output=True,text=True,check=True,timeout=30)
            tests=json.loads(listing.stdout)['tests']
            if len(tests)!=len(TESTS) or {item['name'] for item in tests}!=set(TESTS):raise RuntimeError('Owned CTest inventory changed; review before running')
            for item in tests:
                expected=TESTS[item['name']];command=item['command']
                if Path(command[0]).resolve()!=BUILD/'Release'/expected[0] or tuple(command[1:])!=expected[1:]:raise RuntimeError('Unexpected owned test command')
                properties={entry['name']:entry['value'] for entry in item['properties']}
                if properties.get('TIMEOUT',0)<=0 or properties['TIMEOUT']>30:raise RuntimeError('Unbounded owned test')
                if bool(properties.get('WILL_FAIL',False))!=(item['name']=='remote_worker_unbound_entry_rejected'):raise RuntimeError('Unexpected negative-test exit policy')
            result=subprocess.run([str(BIN/'ctest.exe'),'--test-dir',str(BUILD),'-C','Release','-V'],stdout=output,stderr=subprocess.STDOUT,timeout=180)
            receipt['stages'].append({'stage':'owned_ctests','count':len(tests),'exit':result.returncode})
            receipt['source_stable']=before==sources();receipt['passed']=result.returncode==0 and receipt['source_stable']
    except Exception as error:
        receipt['failure_type']=type(error).__name__
    receipt['artifacts']={name:{'sha256':digest(BUILD/'Release'/name),'bytes':(BUILD/'Release'/name).stat().st_size}
        for name in sorted({item[0] for item in TESTS.values()}|{'GuardDeskRemoteBridge.dll'}) if (BUILD/'Release'/name).is_file()}
    receipt['log_sha256']=digest(log)
    manifest=log.with_suffix('.json')
    with manifest.open('x',encoding='utf-8') as output:json.dump(receipt,output,indent=2);output.write('\n')
    print(json.dumps({'manifest':str(manifest),'passed':receipt['passed'],'source_stable':receipt['source_stable'],'deployable':False}))
    if not receipt['passed']:raise SystemExit(1)


if __name__=='__main__':main()
