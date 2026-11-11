"""Static, local-only inventory of the user-selected IP-guard setup payload.

Never executes target code or reads user documents. The custom archive view
normalizes the observed QJ local-header marker only in memory; source bytes
are preserved. Reports are private analysis artifacts, not product releases.
"""
import io
import hashlib
import json
import re
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'runtime/ipguard-installer-analysis-20261022'


class ArchiveView(io.RawIOBase):
    def __init__(self, path, start, length):
        self.file = path.open('rb')
        self.start, self.length, self.position = start, length, 0

    def readable(self): return True
    def seekable(self): return True
    def tell(self): return self.position

    def seek(self, offset, whence=0):
        position = offset if whence == 0 else self.position + offset if whence == 1 else self.length + offset
        if position < 0: raise ValueError('Negative archive seek')
        self.position = position
        return position

    def read(self, count=-1):
        count = min(self.length-self.position, count if count >= 0 else self.length)
        if count <= 0: return b''
        self.file.seek(self.start+self.position)
        position = self.position
        data = self.file.read(count)
        # The first local record has QJ instead of PK; all central records
        # and later local records use standard ZIP signatures.
        if position < 2:
            data = b'PK'[position:min(2, position+len(data))] + data[max(0, 2-position):]
        self.position += len(data)
        return data

    def close(self):
        self.file.close()
        super().close()


def open_archive():
    path = BASE / 'RT_FIRSTPACK.bin'
    # Exact ranges observed in the selected payload's EOCD and central table.
    with path.open('rb') as source:
        source.seek(450352614)
        end = source.read(22)
    assert struct.unpack('<4s4H2IH', end) == (b'PK\x05\x06', 0, 0, 309, 309, 17613, 450334993, 0)
    return zipfile.ZipFile(ArchiveView(path, 8, 450352636-8))


def analyze_members():
    import pefile
    rows=[]
    needles=('FltRegisterFilter','FltStartFiltering','FltSendMessage','FilterConnectCommunicationPort',
             'ExtensionInstallForcelist','NativeMessagingHosts','chrome-extension://',
             'webRequest','ReadDirectoryChangesW','chatgpt.com','NtReadFile','CopyFileW')
    with open_archive() as archive:
        for item in archive.infolist():
            if item.file_size>256*1024*1024:raise ValueError('Oversized entry')
            data=archive.read(item)  # zipfile validates member CRCs on full read.
            row={'member':item.filename,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
            row['indicators']=[n for n in needles if n.encode() in data or n.encode('utf-16le') in data]
            if data.startswith(b'MZ'):
                try:pe=pefile.PE(data=data,fast_load=True)
                except pefile.PEFormatError as exc:
                    row['parse_error']=str(exc);rows.append(row);continue
                pe.parse_data_directories(directories=[1,2,0])
                versions={}
                for group in getattr(pe,'FileInfo',[]):
                    for entry in group:
                        for table in getattr(entry,'StringTable',[]):
                            for key,value in table.entries.items():
                                key=key.decode(errors='replace')
                                if key in ('OriginalFilename','FileDescription','ProductName','FileVersion','CompanyName'):
                                    versions[key]=value.decode(errors='replace')
                row.update(versions=versions,machine=pe.FILE_HEADER.Machine,
                           subsystem=pe.OPTIONAL_HEADER.Subsystem,
                           imports=[{'dll':entry.dll.decode(errors='replace'),
                                     'names':[v.name.decode(errors='replace') for v in entry.imports if v.name]}
                                    for entry in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])],
                           exports=[v.name.decode(errors='replace') for v in getattr(getattr(pe,'DIRECTORY_ENTRY_EXPORT',None),'symbols',[]) if v.name])
                pe.close()
            elif data.startswith(b'PK'):
                try:
                    with zipfile.ZipFile(io.BytesIO(data)) as nested:
                        row['zip_members']=[{'name':z.filename,'bytes':z.file_size} for z in nested.infolist()]
                except zipfile.BadZipFile:row['zip_error']='unrecognized ZIP'
            rows.append(row)
    report={'source_evidence':'evidence/rea-ipguard-installer-pe-20261022.json',
            'all_member_crc_checked':True,'members':rows,'executed_target':False,
            'limitations':['Import/string presence proves static inclusion, not runtime execution or upload interception.','No customer configuration payloads are interpreted or reported.']}
    (ROOT/'evidence/ipguard-installer-static-members-20261022.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps({'members_crc_checked':len(rows),'pe_images':sum('versions' in r for r in rows),
                      'non_pe_mz':sum('parse_error' in r for r in rows),
                      'nested_zip_inventories':sum('zip_members' in r for r in rows),
                      'executed_target':False}))
    for r in rows if '--verbose' in sys.argv else []:
        strong=[n for n in r['indicators'] if n not in ('NtReadFile','CopyFileW','ReadDirectoryChangesW')]
        if r.get('subsystem')==1 or strong or 'zip_members' in r:
            print(json.dumps({'member':r['member'],'versions':r.get('versions'),
                              'subsystem':r.get('subsystem'),'indicators':strong,
                              'nested_count':len(r.get('zip_members',[]))}))


if __name__ == '__main__' and '--analyze' in sys.argv:
    analyze_members()
elif __name__ == '__main__':
    with open_archive() as archive:
        rows = []
        for item in archive.infolist():
            if item.file_size > 256*1024*1024: raise ValueError('Entry exceeds static-analysis budget')
            with archive.open(item) as source:
                header = source.read(64)
            rows.append({'member': item.filename, 'bytes': item.file_size,
                         'compressed': item.compress_size, 'encrypted': bool(item.flag_bits & 1),
                         'header_hex': header[:12].hex(), 'crc32': format(item.CRC, '08x')})
        report = {'source_evidence': 'evidence/rea-ipguard-installer-pe-20261022.json',
                  'normalization': 'view starts at payload offset 8; QJ local marker normalized to PK in memory; trailer excluded using verified EOCD',
                  'members': rows, 'member_count': len(rows),
                  'uncompressed_bytes': sum(row['bytes'] for row in rows),
                  'executed_target': False, 'configuration_changed': False}
        (ROOT/'evidence/ipguard-installer-members-20261022.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
        print(json.dumps({'count':len(rows),'uncompressed_bytes':report['uncompressed_bytes'],
                          'members':rows[:8], 'header_counts': {h:sum(r['header_hex'].startswith(h) for r in rows) for h in ('4d5a','504b','7b','3c')}}))
