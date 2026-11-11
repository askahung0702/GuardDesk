"""Small shared path/hash checks. No Agent, database or key-management imports."""
import hashlib
import os
from pathlib import Path


def plain(path):
    path=Path(path).absolute()
    for part in (path,*path.parents):
        if os.path.lexists(part) and (part.is_symlink() or getattr(part.lstat(),'st_file_attributes',0)&0x400):
            raise ValueError('更新路徑不可包含 junction／符號連結')
    return path


def file_hash(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
