"""Read-only Windows Installer metadata/detection APIs. Never run on upload."""
import ctypes
from ctypes import wintypes as w
from contextlib import contextmanager
from .software_contract import product_code, version


def api():
    dll=ctypes.WinDLL('msi',use_last_error=True)
    signatures={
        'MsiOpenDatabaseW':[w.LPCWSTR,w.LPCWSTR,ctypes.POINTER(w.UINT)],
        'MsiCloseHandle':[w.UINT],
        'MsiDatabaseOpenViewW':[w.UINT,w.LPCWSTR,ctypes.POINTER(w.UINT)],
        'MsiViewExecute':[w.UINT,w.UINT], 'MsiViewFetch':[w.UINT,ctypes.POINTER(w.UINT)],
        'MsiRecordGetStringW':[w.UINT,w.UINT,w.LPWSTR,ctypes.POINTER(w.DWORD)],
        'MsiGetSummaryInformationW':[w.UINT,w.LPCWSTR,w.UINT,ctypes.POINTER(w.UINT)],
        'MsiSummaryInfoGetPropertyW':[w.UINT,w.UINT,ctypes.POINTER(w.UINT),ctypes.POINTER(ctypes.c_int),ctypes.POINTER(w.FILETIME),w.LPWSTR,ctypes.POINTER(w.DWORD)],
        'MsiGetProductInfoExW':[w.LPCWSTR,w.LPCWSTR,w.DWORD,w.LPCWSTR,w.LPWSTR,ctypes.POINTER(w.DWORD)]}
    for name,args in signatures.items():
        getattr(dll,name).argtypes=args;getattr(dll,name).restype=w.UINT
    return dll


def check(code):
    if code:raise OSError(code,'Windows Installer metadata API failed')


@contextmanager
def handle(dll,fn,*args):
    out=w.UINT();check(fn(*args,ctypes.byref(out)))
    try:yield out.value
    finally:dll.MsiCloseHandle(out)


def rows(dll,db,sql,columns,limit=100000):
    with handle(dll,dll.MsiDatabaseOpenViewW,db,sql) as view:
        check(dll.MsiViewExecute(view,0))
        for _ in range(limit+1):
            record=w.UINT();code=dll.MsiViewFetch(view,ctypes.byref(record))
            if code==259:return
            check(code)
            try:
                values=[]
                for i in range(1,columns+1):
                    buf=ctypes.create_unicode_buffer(4096);size=w.DWORD(4096)
                    check(dll.MsiRecordGetStringW(record,i,buf,ctypes.byref(size)))
                    values.append(buf.value)
                yield values
            finally:dll.MsiCloseHandle(record)
        raise ValueError('MSI table exceeds bounded metadata limit')


def inspect(path):
    # Renaming EXE/MSP/MST is insufficient: actual MSI tables and summary required.
    if path.suffix.lower()!='.msi':raise ValueError('Only .msi packages are supported')
    with path.open('rb') as stream:
        if stream.read(8)!=bytes.fromhex('d0cf11e0a1b11ae1'):raise ValueError('Not an MSI compound database')
    dll=api()
    with handle(dll,dll.MsiOpenDatabaseW,str(path),None) as db:
        props=dict(rows(dll,db,'SELECT `Property`, `Value` FROM `Property`',2,4096))
        code=product_code(props.get('ProductCode'));v=props.get('ProductVersion');version(v)
        if props.get('ALLUSERS') not in ('1','2') or props.get('MSIINSTALLPERUSER')=='1':
            raise ValueError('Only vendor-authored per-machine MSI packages are supported')
        with handle(dll,dll.MsiGetSummaryInformationW,db,None,0) as summary:
            typ=w.UINT();number=ctypes.c_int();stamp=w.FILETIME();buf=ctypes.create_unicode_buffer(4096);size=w.DWORD(4096)
            check(dll.MsiSummaryInfoGetPropertyW(summary,15,ctypes.byref(typ),ctypes.byref(number),ctypes.byref(stamp),buf,ctypes.byref(size)))
            compressed=bool(number.value & 2)
        media=list(rows(dll,db,'SELECT `Cabinet` FROM `Media`',1,4096))
        if any(not x[0].startswith('#') for x in media):raise ValueError('MSI must contain its cabinets; external payloads are unsupported')
        installed=0;files=0
        for size,attributes in rows(dll,db,'SELECT `FileSize`, `Attributes` FROM `File`',2):
            attr=int(attributes or '0');files+=1
            if attr & 8192 or (not compressed and not attr & 16384):raise ValueError('MSI contains external uncompressed files')
            installed+=int(size)
        if files and not media:raise ValueError('MSI missing embedded cabinets')
    name=props.get('ProductName','')
    if not 1<=len(name)<=256:raise ValueError('Invalid MSI ProductName')
    return {'name':name,'product_code':code,'version':v,'file_bytes':installed}


def installed_version(code):
    dll=api();code=product_code(code)
    def query(prop):
        buf=ctypes.create_unicode_buffer(256);size=w.DWORD(256)
        rc=dll.MsiGetProductInfoExW(code,None,4,prop,buf,ctypes.byref(size))
        if rc==1605:return None
        check(rc);return buf.value
    if query('State')!='5':return None
    return query('VersionString')
