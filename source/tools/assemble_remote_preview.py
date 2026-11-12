"""Assemble exact native artifacts for offline packaging checks, never deploy.

The output deliberately has no endpoint executable/enrollment/update signature.
It is a numbered internal component snapshot, not an installable Agent release.
Latest receipts must pass and match every current source/artifact byte first.
"""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import zipfile
from tools.remote_build_paths import artifact_root,receipt_path

SOURCE=Path(__file__).resolve().parents[1]
WORKSPACE=SOURCE.parents[1]
NATIVE=artifact_root('CMake')
MEDIA=artifact_root('WebRTC')


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def require_input_backlog_regression(body):
    """Build success alone cannot carry the stale-control fix into a package."""
    stages=body.get('stages',[])
    if not isinstance(stages,list) or not all(isinstance(item,dict) for item in stages):
        raise ValueError('Native input backlog regression receipt is invalid')
    cases=[item for item in stages if item.get('stage')=='remote_media_peer_probe'
        and item.get('arguments')==['--owned-backlog-repro']]
    if (body.get('runtime_tests_requested') is not True or len(cases)!=1
            or cases[0].get('exit')!=0 or cases[0].get('timeout')
            or any(item.get('exit')!=0 for item in stages)):
        raise ValueError('Native input backlog regression must pass before packaging')


def receipt(pattern,media=False):
    path=receipt_path('WebRTC' if media else 'CMake',pattern,WORKSPACE);body=json.loads(path.read_text(encoding='utf-8'))
    if not body.get('passed') or not body.get('sources_stable' if media else 'source_stable'):raise ValueError('Latest build is not a stable passing receipt: '+path.name)
    if media:
        require_input_backlog_regression(body)
        require_grant_stall_regression(body)
        require_preconnect_regression(body)
        require_dynamic_rates_regression(body)
    for name,expected in body['sources'].items():
        source=SOURCE/name
        if media:
            source=SOURCE/'native/remote/webrtc'/name
            if not source.is_file():source=SOURCE/'native/remote'/name
        if not source.is_file() or digest(source)!=expected:raise ValueError('Build source changed after receipt: '+name)
    root=MEDIA if media else NATIVE
    for name,item in body['artifacts'].items():
        if digest(root/name)!=item['sha256']:raise ValueError('Build artifact changed after receipt: '+name)
    return path,body


def require_grant_stall_regression(body):
    """The lifecycle grant fix needs its real DLL runtime regression as well."""
    stages=body.get('stages',[])
    if not isinstance(stages,list) or not all(isinstance(item,dict) for item in stages):
        raise ValueError('Native grant stall regression receipt is invalid')
    cases=[item for item in stages if item.get('stage')=='remote_media_peer_probe'
        and item.get('arguments')==['--owned-grant-stall']]
    if (body.get('runtime_tests_requested') is not True or len(cases)!=1
        or cases[0].get('exit')!=0 or cases[0].get('timeout')
        or any(item.get('exit')!=0 for item in stages)):
        raise ValueError('Native grant stall regression must pass before packaging')


def require_preconnect_regression(body):
    stages=body.get('stages',[])
    if not isinstance(stages,list) or not all(isinstance(item,dict) for item in stages):
        raise ValueError('Native preconnect regression receipt is invalid')
    for mode in ('--owned-preconnect-focus','--owned-window-modal'):
        cases=[item for item in stages if item.get('stage')=='remote_media_peer_probe' and item.get('arguments')==[mode]]
        if (body.get('runtime_tests_requested') is not True or len(cases)!=1
                or cases[0].get('exit')!=0 or cases[0].get('timeout') or any(item.get('exit')!=0 for item in stages)):
            raise ValueError('Native preconnect regression and real modal-window test must pass before packaging')


def require_dynamic_rates_regression(body):
    stages=body.get('stages',[])
    if not isinstance(stages,list) or not all(isinstance(item,dict) for item in stages):
        raise ValueError('Native dynamic rates regression receipt is invalid')
    cases=[item for item in stages if item.get('stage')=='remote_mf_codec_probe'
        and item.get('arguments')==['--dynamic-rates']]
    if (body.get('runtime_tests_requested') is not True or len(cases)!=1
        or cases[0].get('exit')!=0 or cases[0].get('timeout')
        or any(item.get('exit')!=0 for item in stages)):
        raise ValueError('Native dynamic rates regression must pass before packaging')


def main():
    if sys.argv[1:]!=['--assemble-owned']:raise SystemExit('Use --assemble-owned; this does not install, dispatch or publish')
    sys.path.insert(0,str(SOURCE))
    from guarddesk.remote_components import REMOTE_FILES,COHORT_MANIFEST,cohort_manifest,read_cohort
    native,native_body=receipt('remote-m2-native-build-*.json');media,media_body=receipt('webrtc-owned-build-*.json',True)
    sources={name:(NATIVE if name in ('GuardDeskRemoteWorker.exe','GuardDeskRemoteBridge.dll') else MEDIA)/name for name in REMOTE_FILES}
    hashes={name:digest(path) for name,path in sources.items()}
    build_id=hashlib.sha256(json.dumps({'private_wire':2,'media_wire':1,'files':hashes},sort_keys=True,separators=(',',':')).encode()).hexdigest()
    number=1
    while (WORKSPACE/f'runtime/remote-next-cohort-{number:03}').exists():number+=1
    root=WORKSPACE/f'runtime/remote-next-cohort-{number:03}';folder=root/'_internal/remote';folder.mkdir(parents=True)
    for name,path in sources.items():shutil.copyfile(path,folder/name)
    with (folder/COHORT_MANIFEST).open('x',encoding='utf-8') as stream:json.dump(cohort_manifest(hashes,build_id=build_id),stream,sort_keys=True);stream.write('\n')
    read_cohort(root)
    archive=root/'cohort-preview-not-installable.zip'
    with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as output:
        for path in sorted(folder.iterdir()):output.write(path,path.relative_to(root).as_posix())
    expanded=sum(path.stat().st_size for path in folder.iterdir())
    report={'format':1,'status':'internal_component_snapshot_not_installable','deployable':False,
        'build_id':build_id,'files':{name:{'sha256':hashes[name],'bytes':sources[name].stat().st_size} for name in hashes},
        'CMake_receipt':{'path':native.relative_to(WORKSPACE).as_posix(),'sha256':digest(native)},
        'WebRTC_receipt':{'path':media.relative_to(WORKSPACE).as_posix(),'sha256':digest(media)},
        'archive':{'sha256':digest(archive),'compressed_bytes':archive.stat().st_size,'expanded_bytes':expanded},
        'full_Agent_capacity_tested':False,'old_updater_execution_tested':False,'company_product_changed':False}
    with (root/'cohort-preview.json').open('x',encoding='utf-8') as output:json.dump(report,output,indent=2);output.write('\n')
    print(json.dumps({'snapshot':str(root),'build_id':build_id,'compressed_bytes':archive.stat().st_size,'expanded_bytes':expanded,'deployable':False}))


if __name__=='__main__':main()
