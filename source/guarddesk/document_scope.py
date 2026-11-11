"""General file-policy projection; drive metadata only, never tree enumeration."""
import ctypes
import ntpath
import os
import re
from .file_exclusions import excluded


def local_device(name):
    return isinstance(name,str) and re.fullmatch(r'\\Device\\(?:HarddiskVolume[0-9]+|Volume\{[0-9a-f-]{36}\})',name,re.I) is not None


def fixed_drives():
    if os.name!='nt':raise OSError('Windows local-volume metadata required')
    api=ctypes.WinDLL('kernel32',use_last_error=True)
    api.GetLogicalDrives.restype=ctypes.c_uint32
    api.GetDriveTypeW.argtypes=[ctypes.c_wchar_p];api.GetDriveTypeW.restype=ctypes.c_uint32
    mask=api.GetLogicalDrives()
    if not mask:raise ctypes.WinError(ctypes.get_last_error())
    return [chr(65+i)+':\\' for i in range(26) if mask&(1<<i) and api.GetDriveTypeW(chr(65+i)+':\\')==3]


def paths(policy,watch,drives=None):
    if not policy['enabled']:return []
    if policy['scope']=='all_local':return list(fixed_drives() if drives is None else drives)
    if policy['scope']!='managed':raise ValueError('Invalid general file audit scope')
    path=ntpath.normpath(str(watch));drive,tail=ntpath.splitdrive(path)
    if len(drive)!=2 or drive[1]!=':' or not tail.startswith('\\') or path.startswith(('\\\\','\\??\\')):raise ValueError('General native audit requires a local absolute watch path')
    return [path]


def permits(path,policy,watch,runtime=None):
    if not policy['enabled'] or excluded(path,policy['exclude_paths'],runtime):return False
    drive,tail=ntpath.splitdrive(path)
    if len(drive)!=2 or drive[1]!=':' or not tail.startswith('\\'):return False
    if policy['scope']=='all_local':return True
    root=ntpath.normcase(ntpath.normpath(str(watch))).rstrip('\\')
    return ntpath.normcase(ntpath.normpath(path)).startswith(root+'\\')


def early_exclusions(policy,runtime=None):
    # Native filtering is an optimization. The shared Python filter remains
    # authoritative for reserved cache markers, boot files and profile hives.
    extra=list(policy['exclude_paths'])
    extra.extend([os.environ.get('SystemRoot',r'C:\Windows'),
                  os.environ.get('ProgramFiles',r'C:\Program Files'),
                  os.environ.get('ProgramFiles(x86)',r'C:\Program Files (x86)')])
    if runtime:extra.append(str(runtime))
    return extra
