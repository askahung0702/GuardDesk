"""Build-time artifact selection only; never part of endpoint authorization."""
from pathlib import Path
import os,stat
SOURCE=Path(__file__).resolve().parents[1]
WORKSPACE=SOURCE.parents[1]
def owned(path):
    path=Path(path).absolute();runtime=WORKSPACE/'runtime'
    if not path.is_relative_to(runtime) or path==runtime:raise ValueError('Build input escaped checkout runtime')
    for part in [path,*path.parents]:
        if part==WORKSPACE:break
        if part.exists() and part.lstat().st_file_attributes&stat.FILE_ATTRIBUTE_REPARSE_POINT:raise ValueError('Reparse build input')
    if not path.resolve().is_relative_to(runtime.resolve()):raise ValueError('Build input escaped runtime')
    return path.resolve()
def artifact_root(kind):
    names={'CMake':('GUARDDESK_NATIVE_ARTIFACT_ROOT','runtime/remote-next-m3-build/Release'),
           'WebRTC':('GUARDDESK_MEDIA_ARTIFACT_ROOT','runtime/w/src/out/GuardDesk')}
    variable,default=names[kind]
    return owned(os.environ.get(variable,str(WORKSPACE/default)))
def receipt_path(kind,pattern,workspace=None):
    variable={'CMake':'GUARDDESK_NATIVE_RECEIPT','WebRTC':'GUARDDESK_MEDIA_RECEIPT','Python':'GUARDDESK_SOURCE_RECEIPT'}[kind]
    value=os.environ.get(variable)
    if value:return owned(value)
    matches=sorted(((workspace or WORKSPACE)/'runtime').glob(pattern))
    if not matches:raise ValueError('Missing reviewed '+kind+' receipt')
    return matches[-1] if workspace is not None else owned(matches[-1])
