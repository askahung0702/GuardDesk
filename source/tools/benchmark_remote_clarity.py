"""Bounded synthetic encode benchmark, without GDI/employee pixels or real input."""
import base64
import json
import os
from pathlib import Path
import statistics
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from PIL import Image,ImageDraw
from guarddesk import __version__
from guarddesk.remote_codec import encode_clarity,CLARITY_BYTES
from guarddesk.performance import ProcessSampler,background_work


def run():
    sampler=ProcessSampler();measurements=[]
    for size in ((1920,1080),(3840,2160)):
        for content in ('documents','noise'):
            if content=='noise':image=Image.effect_noise(size,90).convert('RGB')
            else:
                image=Image.new('RGB',size,'#f4f5f6');draw=ImageDraw.Draw(image)
                for y in range(10,size[1]-20,24):draw.text((10,y),'Synthetic documents / small text 0123456789 '*7,fill='#15353d',font_size=14)
            baseline=sampler.sample();samples=[];elapsed=[];cpu=time.process_time();wall=time.monotonic()
            try:
                for n in range(5):
                    started=time.monotonic()
                    with background_work():packet=encode_clarity(image)
                    elapsed.append(time.monotonic()-started);samples.append(sampler.sample())
                    kind='png' if 'png' in packet else 'jpeg';encoded_bytes=len(base64.b64decode(packet[kind]))
                    assert encoded_bytes<=CLARITY_BYTES and (packet['width'],packet['height'])==size
                    time.sleep(max(0,.5-(time.monotonic()-started)))
                measurements.append({'dimensions':size,'synthetic_content':content,'frames':5,'codec':kind,'last_frame_bytes':encoded_bytes,
                    'encode_p50_ms':round(statistics.median(elapsed)*1000,1),'encode_max_ms':round(max(elapsed)*1000,1),
                    'cpu_machine_percent':round((time.process_time()-cpu)/(time.monotonic()-wall)*100/(os.cpu_count() or 1),2),
                    'baseline_private_mib':round(baseline.get('private_bytes',0)/1048576,1),
                    'sampled_private_max_mib':round(max(s.get('private_bytes',0) for s in samples)/1048576,1)})
            finally:image.close()
    report={'version':__version__,'passed':True,'measurements':measurements,'logical_cpus':os.cpu_count(),
        'scope':'synthetic image encoding at maximum 2 FPS; current test process only; post-encode memory samples, not allocation peaks',
        'not_measured':['GDI capture','actual agent plus browser/native collectors','network latency/bandwidth','company Defender/EDR overhead','20 physical endpoints'],
        'real_desktop_capture':False}
    (ROOT/f'evidence/remote-clarity-benchmark-{__version__}.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))


if __name__=='__main__':run()
