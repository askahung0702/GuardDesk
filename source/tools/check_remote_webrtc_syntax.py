"""Stage only owned files and syntax-check against the pinned native headers.

No desktop, OS input, elevation or product deployment. Syntax success is not a
link/runtime/media-transport result. Full build uses the staged BUILD.gn.
"""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess

SOURCE=Path(__file__).resolve().parents[1]
WORKSPACE=SOURCE.parents[1]
VENDOR=WORKSPACE/'runtime/w/src'
REVISION='3178a2873c9226a20f678ac902ed979272be0cff'


def stage():
    # This exact, already pinned workspace checkout belongs to DEV; subprocesses
    # may run as the managed sandbox account. Trust only this path for this
    # read-only invocation; never edit global safe.directory or use '*'.
    revision=subprocess.run(['git','-c','safe.directory='+str(VENDOR),'rev-parse','HEAD'],cwd=VENDOR,capture_output=True,text=True,check=True).stdout.strip()
    if revision!=REVISION:raise RuntimeError('WebRTC revision changed; stop')
    owned=VENDOR/'guarddesk_remote'
    if owned.is_symlink() or not owned.resolve().is_relative_to(VENDOR.resolve()):raise RuntimeError('Owned staging path changed')
    owned.mkdir(exist_ok=True);hashes={}
    native_names=('latency.hpp','pointer_flow.hpp','session.cpp','session.hpp','input.cpp','input.hpp','video_geometry.hpp','relay_policy.cpp','relay_policy.hpp','cursor.cpp','cursor.hpp','codec.cpp','codec.hpp','ipc_wire.cpp','ipc_wire.hpp','frame_pool.cpp','frame_pool.hpp','frame_binding.cpp','frame_binding.hpp','h264_frame_binding.cpp','h264_frame_binding.hpp','ipc_peer.cpp','ipc_peer.hpp','capture.hpp','cohort.cpp','cohort.hpp','launch_capsule.cpp','launch_capsule.hpp','broker_api.hpp','media_wire.cpp','media_wire.hpp','ipc_channel.cpp','ipc_channel.hpp','viewer.cpp','viewer.hpp','render.cpp','render.hpp')
    for name in ('BUILD.gn','owned_handoff_probe.cc','transport_probe.cc','owned_video_probe.hpp','owned_control_probe.hpp','mf_codec_adapter.cc','mf_codec_adapter.hpp','mf_codec_probe.cc','mf_hardware_probe.cc','frame_bridge.cc','frame_bridge.hpp','media_peer.cc','media_peer.hpp','mis_native.cc','mis_native.hpp','media_peer_probe.cc','media_entry.cc','media_entry_token.hpp','media_token_probe.cc','relay_probe.cc','network_guard.cc','network_guard.hpp',*native_names):
        source=SOURCE/'native/remote'/('' if name in native_names else 'webrtc')/name
        checksum=hashlib.sha256(source.read_bytes()).hexdigest();destination=owned/name
        if not destination.is_file() or hashlib.sha256(destination.read_bytes()).hexdigest()!=checksum:
            shutil.copyfile(source,destination)
        hashes[name]=checksum
    (owned/'guarddesk-source-manifest.json').write_text(json.dumps(hashes,indent=2)+'\n',encoding='utf-8')
    return hashes


def main():
    hashes=stage()
    target='obj/guarddesk_remote/remote_transport_probe/transport_probe.obj'
    command=subprocess.run([str(VENDOR/'third_party/ninja/ninja.exe'),'-C','out/GuardDesk','-t','commands',target],
        cwd=VENDOR,capture_output=True,text=True,check=True).stdout.splitlines()[-1]
    if '../../guarddesk_remote/transport_probe.cc' not in command or 'clang-cl.exe' not in command:raise RuntimeError('Unexpected syntax command')
    failed=False
    for name in ('transport_probe.cc','mf_codec_adapter.cc','mf_codec_probe.cc','codec.cpp'):
        value=command.replace(' /c ',' -fsyntax-only ').replace('/Fo'+target,'/Foowned-syntax-only.obj')
        value=value.replace('../../guarddesk_remote/transport_probe.cc','../../guarddesk_remote/'+name)
        value+=' /EHsc -I../../guarddesk_remote'
        result=subprocess.run(value,executable=str(VENDOR/'third_party/llvm-build/Release+Asserts/bin/clang-cl.exe'),
            cwd=VENDOR/'out/GuardDesk',stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        log=WORKSPACE/'runtime'/('webrtc-syntax-'+name.replace('.','-')+'.log')
        log.write_text(result.stdout,encoding='utf-8')
        print(json.dumps({'source':name,'syntax_exit':result.returncode,'source_sha256':hashes[name]}),flush=True)
        if result.returncode:
            failed=True
            for line in result.stdout.splitlines():
                if 'error:' in line or 'warning:' in line:print(line,flush=True)
    if failed:raise SystemExit(1)


if __name__=='__main__':main()
