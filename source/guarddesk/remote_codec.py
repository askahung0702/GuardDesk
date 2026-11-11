"""Bounded desktop frames and input vocabulary shared by native components."""
import base64
import io
import struct

MAX_BYTES = 600000
MAX_WIDTH, MAX_HEIGHT = 1920, 1080
CLARITY_BYTES = 2 * 1024 * 1024
CLARITY_BODY = 3 * 1024 * 1024
CLARITY_DIMENSION, CLARITY_PIXELS = 3840, 3840 * 2160
KEYS = set(range(48, 91)) | set(range(112, 124)) | {
    8,9,13,16,17,18,19,20,27,32,33,34,35,36,37,38,39,40,44,45,46,91,92,
    144,145,186,187,188,189,190,191,192,219,220,221,222,226,
}


def jpeg_size(data):
    if data[:2] != b'\xff\xd8' or data[-2:] != b'\xff\xd9':
        raise ValueError('Invalid JPEG')
    at = 2
    while at < len(data):
        if data[at] != 255: raise ValueError('Invalid JPEG marker')
        while at < len(data) and data[at] == 255: at += 1
        if at >= len(data): break
        marker = data[at]; at += 1
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7: continue
        if at+2 > len(data): break
        length = int.from_bytes(data[at:at+2], 'big')
        if length < 2 or at+length > len(data): break
        if marker in (0xC0, 0xC1, 0xC2):
            if length < 8 or data[at+2] != 8: break
            height,width = struct.unpack('>HH', data[at+3:at+7])
            return width,height
        if marker == 0xDA: break
        at += length
    raise ValueError('Missing JPEG dimensions')


def validate_frame(frame, jpeg=True, high_resolution=False):
    if not isinstance(frame,dict): raise ValueError('Invalid frame')
    kind = 'jpeg' if 'jpeg' in frame else 'png'
    if set(frame) != {kind,'width','height'} or (kind == 'jpeg' and not jpeg): raise ValueError('Invalid frame fields')
    if any(type(frame.get(k)) is not int for k in ('width','height')): raise ValueError('Invalid frame dimensions')
    width,height=frame['width'],frame['height']
    if high_resolution:
        valid=1<=width<=CLARITY_DIMENSION and 1<=height<=CLARITY_DIMENSION and width*height<=CLARITY_PIXELS
    else:valid=1<=width<=MAX_WIDTH and 1<=height<=MAX_HEIGHT
    if not valid:raise ValueError('Frame dimensions too large')
    budget=CLARITY_BYTES if high_resolution else MAX_BYTES
    value = frame[kind]
    if not isinstance(value,str) or len(value)>4*((budget+2)//3): raise ValueError('Frame too large')
    try: data = base64.b64decode(value,validate=True)
    except (ValueError,TypeError): raise ValueError('Invalid frame encoding') from None
    if len(data)>budget: raise ValueError('Frame too large')
    if kind == 'jpeg': size = jpeg_size(data)
    else:
        if data[:8] != b'\x89PNG\r\n\x1a\n' or len(data)<25: raise ValueError('Invalid PNG')
        size = struct.unpack('>II',data[16:24])
    if size != (frame['width'],frame['height']): raise ValueError('Frame dimensions mismatch')
    return kind,data


def decode_frame(frame, high_resolution=False):
    from PIL import Image
    kind,data = validate_frame({k:v for k,v in frame.items() if k in ('png','jpeg','width','height')},high_resolution=high_resolution)
    try:
        with Image.open(io.BytesIO(data), formats=['PNG','JPEG']) as image:
            if image.size != (frame['width'],frame['height']) or image.format != ('JPEG' if kind=='jpeg' else 'PNG'):
                raise ValueError('Frame decoder mismatch')
            image.load()
            return image.convert('RGB')
    except Image.DecompressionBombError:raise ValueError('Frame decoding limit exceeded') from None


def encode_jpeg(image, quality=78, budget=MAX_BYTES):
    output=io.BytesIO();image.save(output,format='JPEG',quality=quality,subsampling=0,optimize=False)
    data=output.getvalue()
    if len(data)>budget: raise ValueError('JPEG frame exceeds transport budget')
    return {'width':image.width,'height':image.height,'jpeg':base64.b64encode(data).decode('ascii')}


def encode_clarity(image):
    """Lossless text first; bounded JPEG fallback without silently shrinking pixels."""
    if not (1<=image.width<=CLARITY_DIMENSION and 1<=image.height<=CLARITY_DIMENSION and image.width*image.height<=CLARITY_PIXELS):
        raise ValueError('Clarity frame dimensions too large')
    output=io.BytesIO();image.save(output,format='PNG',compress_level=1)
    data=output.getvalue()
    output.close()
    if len(data)<=CLARITY_BYTES:
        return {'width':image.width,'height':image.height,'png':base64.b64encode(data).decode('ascii')}
    del data
    for quality in (94,85,70,50,30,15,5):
        try:return encode_jpeg(image,quality,budget=CLARITY_BYTES)
        except ValueError:continue
    raise ValueError('Clarity frame exceeds transport budget')
