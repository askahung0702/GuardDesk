"""Reviewed entry points; field maintenance/integration is intentionally separate."""
from pathlib import Path
import argparse,json,subprocess,sys,unittest
from worktree import environment,python,stage,webrtc_source
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['stage','check','test','native','service','document','webrtc','assemble','notices'])
    p.add_argument('--webrtc-source',type=Path,help='Explicit existing pinned WebRTC checkout; no binary reuse')
    a=p.parse_args()
    if a.command=='check':
        subprocess.run([sys.executable,str(ROOT/'dev/validate_source.py')],check=True);return
    if a.command=='notices':
        subprocess.run([sys.executable,str(ROOT/'dev/prepare_notices.py')],check=True);return
    target,record=stage(ROOT)
    if a.command=='stage':print(json.dumps({'staged_files':len(record['files']),'path':str(target)}));return
    exe=python(ROOT);env=environment(ROOT)
    if a.command=='test':
        subprocess.run([str(exe),str(ROOT/'dev/run_unit.py')],cwd=target,env=env,check=True,timeout=180);return
    commands={
        'native':['-m','tools.build_remote_native','--owned-tests'],
        'service':['-m','tools.build_remote_service'],
        'document':['-m','tools.build_document_trace'],
        'webrtc':['-m','tools.build_remote_webrtc','--run-owned-ui-tests'],
        'assemble':['-m','tools.assemble_remote_preview','--assemble-owned'],
    }
    if a.webrtc_source is not None and a.command!='webrtc':raise ValueError('--webrtc-source applies only to webrtc rebuild')
    if a.command=='webrtc':env['GUARDDESK_WEBRTC_SOURCE']=str(webrtc_source(ROOT,a.webrtc_source))
    subprocess.run([str(exe),*commands[a.command]],cwd=target,env=env,check=True)
if __name__=='__main__':main()
