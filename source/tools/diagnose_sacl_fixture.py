"""Own disposable fixture only: compare minimal SACL handle access masks."""
import ctypes,json,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from guarddesk.document_sacl import WindowsSacl,add_audit
from guarddesk.process_audit import security_privilege

def main():
    b=WindowsSacl();w=b.w;results=[]
    b.a.IsValidAcl.argtypes=[w.LPVOID];b.a.IsValidAcl.restype=w.BOOL
    area=ROOT/'runtime/document-native-os';area.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='acl-variant-',dir=area) as d:
        p=Path(d)/'owned.dat';p.write_bytes(b'fixture')
        for access in (0x01000080,0x01020080):
            row={'access':hex(access)};results.append(row)
            with security_privilege(b.a):
                h=b.k.CreateFileW(str(p),access,7,None,3,0x02200000,None)
                if h==w.HANDLE(-1).value:row['open_error']=ctypes.get_last_error();continue
                changed=False
                try:
                    before=b.get(h);after=add_audit(before,1);raw=ctypes.create_string_buffer(after)
                    row['acl_valid']=bool(b.a.IsValidAcl(raw));row['before']=before.hex() if before else None
                    code=b.a.SetSecurityInfo(h,1,8,None,None,None,raw);row['set_result']=code
                    if not code:
                        changed=True;row['readback']=b.get(h)==after
                finally:
                    if changed:
                        b.set(h,before);row['restored']=b.get(h)==before
                    b.k.CloseHandle(h)
    (ROOT/'evidence/sacl-access-variants-0.4.49.json').write_text(json.dumps(results,indent=2),encoding='utf-8')

if __name__=='__main__':main()
