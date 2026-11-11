"""MSI-only software deployment wire contract, separate from Agent updates."""
import math
import re

PURPOSE = 'guarddesk-software-msi-v1'
CAPABILITY = 'software_msi_v1'
GIB = 1024 ** 3
MAX_PACKAGE = 64 * GIB  # wire/worker ceiling; center default is configurable 8 GiB
LIBRARY_LIMIT = 32 * GIB
MAX_PACKAGES = 100
TERMINAL = {'succeeded', 'already_installed', 'reboot_required', 'failed', 'cancelled'}
STATES = TERMINAL | {'queued', 'downloading', 'installing', 'review_required'}


def hex_id(value, length):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{%d}' % length, value):
        raise ValueError('Invalid software identifier')
    return value


def product_code(value):
    if not isinstance(value, str) or not re.fullmatch(r'\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}', value):
        raise ValueError('Invalid MSI ProductCode')
    return value.upper()


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{1,3}\.\d{1,3}\.\d{1,5}', value):
        raise ValueError('MSI requires a three-part ProductVersion')
    parts = tuple(map(int, value.split('.')))
    if any(a > b for a, b in zip(parts, (255, 255, 65535))):
        raise ValueError('MSI ProductVersion out of range')
    return parts


def manifest(value):
    fields = {'purpose', 'sha256', 'bytes', 'name', 'product_code', 'version', 'install_bytes', 'publisher'}
    if not isinstance(value, dict) or set(value) != fields or value['purpose'] != PURPOSE:
        raise ValueError('Not a software MSI manifest')
    hex_id(value['sha256'], 64)
    product_code(value['product_code']); version(value['version'])
    if type(value['bytes']) is not int or not 0 < value['bytes'] <= MAX_PACKAGE:
        raise ValueError('MSI package exceeds software limit')
    if type(value['install_bytes']) is not int or not value['bytes'] <= value['install_bytes'] <= 256 * GIB:
        raise ValueError('Invalid installation space budget')
    for key in ('name', 'publisher'):
        if not isinstance(value[key], str) or not 1 <= len(value[key]) <= 256 or any(ord(c) < 32 for c in value[key]):
            raise ValueError('Invalid MSI metadata')
    return value


def job(value, device, now):
    if not isinstance(value, dict) or set(value) != {'purpose','id','device_id','expires','package'} or value['purpose'] != PURPOSE:
        raise ValueError('Not a software job')
    hex_id(value['id'],32)
    if value['device_id'] != device:raise ValueError('Software job belongs to another endpoint')
    expiry=value['expires']
    if type(expiry) not in (int,float) or not math.isfinite(expiry) or not now < expiry <= now+8*86400:
        raise ValueError('Software job expired')
    manifest(value['package'])
    return value


def outcome(code, detected, wanted):
    """An exit code is not installation detection; never infer Defender blocking."""
    if code == 1641:return 'review_required', 'INSTALLER_INITIATED_REBOOT'
    if code not in (0,3010):return 'failed', 'MSI_EXIT_' + str(code)
    if detected != wanted:return 'review_required', 'PRODUCT_DETECTION_MISMATCH'
    return ('reboot_required' if code == 3010 else 'succeeded'), ''
