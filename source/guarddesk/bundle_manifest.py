"""Read-only package/ACL verification shared by center and endpoint."""
import hashlib
import json
import os
from . import update_packages as packages
METADATA="_internal/agent-release.json"

class BundleError(ValueError):
    def __init__(self,code,diagnostic=None):super().__init__(code);self.code=code;self.diagnostic=diagnostic


def inspect(source,version,stop):
    source=packages.plain(source);meta=packages.plain(source/METADATA)
    if os.name=='nt':
        from .source_permissions import check_source,SourcePermissionError
        try:
            check_source(source,stop)
        except InterruptedError:raise
        except SourcePermissionError as exc:
            raise BundleError('source_not_private',{'path':exc.path[:512],'reason':exc.reason}) from None
        except OSError:raise BundleError('source_not_private',{'path':str(source)[:512],'reason':'permission_unreadable'}) from None
    if not meta.is_file():raise BundleError('missing_manifest')
    if meta.stat().st_size>2*1024*1024:raise BundleError('integrity_failed')
    raw=meta.read_bytes();body=json.loads(raw)
    if not isinstance(body,dict) or set(body)!={'format','version','files'} or body['format']!=1 or body['version']!=version:raise BundleError('integrity_failed')
    packages.version(version);files=body['files']
    if not isinstance(files,dict) or not 3<=len(files)<packages.MAX_FILES or not {'GuardDesk.exe','GuardDeskAgent.exe'}<=files.keys() or METADATA in files:raise BundleError('integrity_failed')
    expected={**files,METADATA:hashlib.sha256(raw).hexdigest()}
    found=set();total=0;count=0
    for path in source.rglob('*'):
        if stop.is_set():raise InterruptedError('stopped')
        count+=1
        if count>2*packages.MAX_FILES:raise BundleError('integrity_failed')
        packages.plain(path)
        if not path.is_file():continue
        name=packages.safe_name(path.relative_to(source).as_posix());found.add(name)
        digest=expected.get(name)
        if not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest):raise BundleError('integrity_failed')
        total+=path.stat().st_size
        if total>packages.MAX_TOTAL:raise BundleError('integrity_failed')
        value=hashlib.sha256()
        with path.open('rb') as stream:
            while chunk:=stream.read(65536):
                if stop.is_set():raise InterruptedError('stopped')
                value.update(chunk)
        if value.hexdigest()!=digest:raise BundleError('integrity_failed')
    if found!=set(expected):raise BundleError('integrity_failed')
    return expected

