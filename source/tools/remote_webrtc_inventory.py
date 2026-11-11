"""Record actual Ninja inputs and nearby license metadata for owned probes.

This is a build-input inventory, not a claim about final linker dead stripping,
redistribution compliance, vulnerabilities or a finished product SBOM.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
from tools.check_remote_webrtc_syntax import VENDOR,WORKSPACE,REVISION


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    if sys.argv[1:]!=['--owned-probes']:raise SystemExit('Use --owned-probes')
    actual=subprocess.run(['git','-c','safe.directory='+str(VENDOR.resolve()).replace('\\','/'),'rev-parse','HEAD'],cwd=VENDOR,capture_output=True,text=True,check=True).stdout.strip()
    if actual!=REVISION:raise RuntimeError('Pinned source changed')
    build=VENDOR/'out/GuardDesk';ninja=VENDOR/'third_party/ninja/ninja.exe'
    targets=['remote_transport_probe.exe','remote_control_probe.exe','remote_mf_codec_probe.exe','remote_video_probe.exe',
        'remote_pipeline_probe.exe','remote_media_peer_probe.exe','remote_hardware_codec_probe.exe','remote_media_token_probe.exe',
        'GuardDeskRemoteMedia.exe','GuardDeskMisNative.dll']
    inputs={};metadata={};outside=0;reviewed_directories=set()
    for target in targets:
        exe=build/target
        if not exe.is_file():raise RuntimeError('Build all owned probes first')
        result=subprocess.run([str(ninja),'-t','inputs',target],cwd=build,capture_output=True,text=True,check=True)
        names=[]
        lines=result.stdout.splitlines()
        if len(lines)>20000:raise RuntimeError('Owned probe input inventory exceeded its bounded review size')
        for value in lines:
            path=(build/value.strip()).resolve()
            if not path.is_relative_to(VENDOR.resolve()):outside+=1;continue
            if not path.is_file():continue
            name=path.relative_to(VENDOR).as_posix();names.append(name)
            if name not in inputs:inputs[name]={'sha256':digest(path)}
            # Only walk ancestors of actual inputs; never scan the source tree.
            current=path.parent
            while current.is_relative_to(VENDOR):
                if current in reviewed_directories:break
                reviewed_directories.add(current)
                for label in ('LICENSE','LICENSE.txt','LICENSE.md','COPYING','README.chromium'):
                    candidate=current/label
                    if candidate.is_file():
                        key=candidate.relative_to(VENDOR).as_posix()
                        if key not in metadata:metadata[key]={'sha256':digest(candidate),'bytes':candidate.stat().st_size}
                if current==VENDOR:break
                current=current.parent
        inputs_for_target=sorted(set(names))
        inputs['@'+target]={'artifact_sha256':digest(exe),'artifact_bytes':exe.stat().st_size,'inputs':inputs_for_target}
    base=WORKSPACE/'evidence/maintenance/remote-next-m2-20261030';number=1
    while (base/f'webrtc-build-input-inventory-{number:03}.json').exists():number+=1
    report={'format':1,'scope':'Actual Ninja build inputs and ancestor license metadata; not a final binary/product SBOM',
        'revision':REVISION,'inputs':inputs,'license_metadata':metadata,'outside_vendor_inputs_excluded':outside,
        'redistribution_review_complete':False,'vulnerability_review_complete':False,'product_deployable':False}
    output=base/f'webrtc-build-input-inventory-{number:03}.json'
    with output.open('x',encoding='utf-8') as stream:json.dump(report,stream,indent=2);stream.write('\n')
    print(json.dumps({'inventory':str(output),'input_entries':len(inputs),'license_metadata_files':len(metadata),'deployable':False}))


if __name__=='__main__':main()
