"""Synthetic encoding/decoding only; does not capture or control a desktop."""
import base64
import io
import json
from pathlib import Path
import statistics
import sys
import time

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
from PIL import Image,__version__
from native_remote_smoke import sample
from guarddesk.remote_codec import encode_jpeg,decode_frame


def run():
    assert __version__=='13.0.0',__version__
    reports=[]
    image=sample()
    try:
        for name,picture in [('synthetic office layout',image),('synthetic patterned image',Image.effect_noise((1600,900),35).convert('RGB'))]:
            enc=[];dec=[];png=[];packet=None
            for quality in (78,65,50):
                try:encode_jpeg(picture,quality);break
                except ValueError:
                    if quality==50:raise
            for n in range(25):
                start=time.perf_counter();packet=encode_jpeg(picture,quality);enc.append((time.perf_counter()-start)*1000)
                start=time.perf_counter();decoded=decode_frame(packet);decoded.close();dec.append((time.perf_counter()-start)*1000)
                output=io.BytesIO();start=time.perf_counter();picture.save(output,format='PNG',compress_level=3);png.append((time.perf_counter()-start)*1000)
            reports.append({'fixture':name,'dimensions':list(picture.size),'quality':quality,'jpeg_bytes':len(base64.b64decode(packet['jpeg'])),
                            'PNG_same_resolution_bytes':len(output.getvalue()),'jpeg_encode_p50_ms':round(statistics.median(enc),2),
                            'jpeg_decode_p50_ms':round(statistics.median(dec),2),'PNG_encode_p50_ms':round(statistics.median(png),2),
                            'samples':len(enc)})
            if picture is not image:picture.close()
    finally:image.close()
    result={'version':'0.4.14','Pillow':__version__,'synthetic_codec_only':True,'results':reports,
            'not_measured':['real GDI capture','real endpoint CPU and memory','cross-host network','real SendInput latency','Defender and Server workload']}
    (ROOT/'evidence/native-remote-codec-benchmark.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result))


if __name__=='__main__':run()
