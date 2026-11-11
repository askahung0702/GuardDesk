"""Build/run the owned native probes. Never install a product or toolchain.

Requires the separately approved, pinned checkout and Microsoft development
tools. All generated outputs are under runtime/w; previous logs stay intact.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
from tools.check_remote_webrtc_syntax import stage,VENDOR,WORKSPACE,REVISION,SOURCE

ARGS='is_debug=false symbol_level=0 is_component_build=false rtc_include_tests=false rtc_build_examples=false rtc_use_h264=false target_cpu="x64"'


def main():
    if sys.argv[1:] not in ([],['--run-owned-tests'],['--run-owned-ui-tests']):raise SystemExit('Use --run-owned-tests or --run-owned-ui-tests (nonactivating synthetic window)')
    visible_ui=sys.argv[1:]==['--run-owned-ui-tests']
    hashes=stage();env=os.environ.copy()
    env.update(DEPOT_TOOLS_UPDATE='0',DEPOT_TOOLS_WIN_TOOLCHAIN='0',DEPOT_TOOLS_METRICS='0',
        DEPOT_TOOLS_COLLECT_METRICS='0',GYP_MSVS_VERSION='2026',
        vs2026_install=r'C:\Program Files (x86)\Microsoft Visual Studio\2026\BuildTools')
    env['PATH']=str(WORKSPACE/'runtime/toolchains/depot_tools')+os.pathsep+env.get('PATH','')
    number=1
    while (WORKSPACE/f'runtime/webrtc-owned-build-{number:03}.log').exists():number+=1
    log=WORKSPACE/f'runtime/webrtc-owned-build-{number:03}.log'
    metadata={'revision':REVISION,'sources':hashes,'args':ARGS,'jobs':2,'stages':[],'visible_owned_ui_requested':visible_ui,'product_installed':False,'deployable':False}
    with log.open('x',encoding='utf-8') as output:
        for label,command in (
            ('gn',[str(VENDOR/'buildtools/win/gn.exe'),'gen','out/GuardDesk','--root-target=//guarddesk_remote:owned_probes','--args='+ARGS]),
            ('ninja',[str(VENDOR/'third_party/ninja/ninja.exe'),'-C','out/GuardDesk','-j','2','owned_probes'])):
            result=subprocess.run(command,cwd=VENDOR,env=env,stdout=output,stderr=subprocess.STDOUT)
            metadata['stages'].append({'stage':label,'exit':result.returncode})
            print(json.dumps(metadata['stages'][-1]),flush=True)
            if result.returncode:break
        if metadata['stages'][-1]['exit']==0 and sys.argv[1:]:
            cases=[('remote_mf_codec_probe',[]),('remote_mf_codec_probe',['--expired-binding']),('remote_transport_probe',[]),('remote_control_probe',[]),('remote_video_probe',[]),('remote_video_probe',['--owned-1080p']),('remote_pipeline_probe',[]),('remote_media_peer_probe',[]),('remote_media_peer_probe',['--owned-input-stress']),('remote_media_peer_probe',['--owned-backlog-repro']),('remote_hardware_codec_probe',[]),('remote_media_token_probe',[]),('remote_relay_probe',[])]
            cases.append(('remote_media_peer_probe',['--owned-grant-stall']))
            cases.append(('remote_media_peer_probe',['--owned-preconnect-focus']))
            if visible_ui:
                cases.append(('remote_media_peer_probe',['--owned-window-modal']))
                cases.append(('remote_owned_handoff_probe',[]))
            metadata['expected_runtime_cases']=len(cases)
            for name,arguments in cases:
                exe=VENDOR/'out/GuardDesk'/(name+'.exe')
                try:
                    result=subprocess.run([str(exe),*arguments],cwd=exe.parent,env=env,stdout=output,stderr=subprocess.STDOUT,timeout=90)
                    outcome={'stage':name,'arguments':arguments,'exit':result.returncode}
                except subprocess.TimeoutExpired:outcome={'stage':name,'arguments':arguments,'timeout':True,'exit':124}
                metadata['stages'].append(outcome);print(json.dumps(outcome),flush=True)
                if outcome['exit']:break
    after={}
    for name in hashes:
        source=SOURCE/'native/remote/webrtc'/name
        if not source.is_file():source=SOURCE/'native/remote'/name
        after[name]=hashlib.sha256(source.read_bytes()).hexdigest()
    metadata['sources_after']=after
    metadata['sources_stable']=after==hashes
    metadata['passed']=metadata['sources_stable'] and all(item['exit']==0 for item in metadata['stages'])
    metadata['runtime_tests_requested']=bool(sys.argv[1:])
    artifacts={}
    for name in ('remote_transport_probe.exe','remote_control_probe.exe','remote_mf_codec_probe.exe','remote_video_probe.exe','remote_pipeline_probe.exe','remote_media_peer_probe.exe','remote_owned_handoff_probe.exe','GuardDeskMisNative.dll','GuardDeskRemoteMedia.exe','remote_hardware_codec_probe.exe','remote_media_token_probe.exe','remote_relay_probe.exe'):
        path=VENDOR/'out/GuardDesk'/name
        if path.is_file():
            with path.open('rb') as stream:checksum=hashlib.file_digest(stream,'sha256').hexdigest()
            artifacts[name]={'sha256':checksum,'bytes':path.stat().st_size}
    metadata['artifacts']=artifacts
    manifest=log.with_suffix('.json');manifest.write_text(json.dumps(metadata,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'log':str(log),'manifest':str(manifest),'passed':metadata['passed'],'deployable':False}),flush=True)
    if not metadata['passed']:raise SystemExit(1)


if __name__=='__main__':main()
