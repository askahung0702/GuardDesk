"""Restore checked license text/provenance into generated runtime, no programs."""
from pathlib import Path
import json,shutil
from worktree import contained,digest
ROOT=Path(__file__).resolve().parents[1]
def main():
    source=ROOT/'licenses/remote';body=json.loads((source/'notice-manifest.json').read_text())
    runtime=contained(ROOT,ROOT/'runtime');runtime.mkdir(exist_ok=True)
    destination=contained(runtime,runtime/'remote-native-notices-001')
    for name,wanted in body['files'].items():
        if digest(contained(source,source/name))!=wanted:raise ValueError('License source changed')
    expected='runtime/webrtc-product-notices-003/receipt.json'
    if body['generator_receipt']['path']!=expected:raise ValueError('Unreviewed generator receipt path')
    proof=ROOT/'licenses/remote-generator-receipt.json'
    if digest(proof)!=body['generator_receipt']['sha256']:raise ValueError('License generator provenance changed')
    for p in source.rglob('*'):
        if p.is_file():
            target=contained(runtime,destination/p.relative_to(source));target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(p,target)
    target=contained(runtime,ROOT/expected);target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(proof,target)
    print('Notices prepared: runtime/remote-native-notices-001')
if __name__=='__main__':main()
