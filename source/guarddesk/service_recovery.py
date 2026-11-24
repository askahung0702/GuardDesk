"""Fixed security hold for the installed service; no restart or repair authority."""
import re
import struct
from pathlib import Path

MARKER='service-security-hold.bin'
MESSAGE=struct.Struct('<4sI24s')


def marker_bytes(did,error):
    if not isinstance(did,str) or not re.fullmatch('[0-9a-f]{24}',did):
        raise ValueError('Invalid recovery identity')
    if type(error) is not int or error not in (225,226):
        raise ValueError('Invalid recovery security reason')
    return MESSAGE.pack(b'GDS1',error,did.encode('ascii'))


def persist_security_hold(agent,error):
    """Called only after an actual 225/226 rejection by the installed worker.

    Keep the first marker. A corrupt or different identity marker is a hold,
    never permission to clear the marker or launch another worker.
    """
    raw=marker_bytes(agent.config['device_id'],error)
    from .machine_service import enabled
    from .remote_trial import enabled as trial
    from .machine_agent import eligible
    if not (enabled() or trial()) or not eligible(agent):return False
    from .update_native import folder,protected_tree
    root=folder(35)/'USBControl'/agent.config['device_id']
    if Path(agent.config_path)!=root/'config.json':raise PermissionError('Recovery configuration mismatch')
    from .protected_files import ProtectedFiles
    for parent in (folder(35),root.parent,root):protected_tree(parent,recursive=False)
    # The supervisor intentionally preserves existing helpers after225/226.
    # Make the OS fence durable first, rather than waiting for worker exit.
    import sys
    from .remote_service import Service,description
    Service().disable_for_recovery(description(Path(sys.executable),agent.config_path))
    path=root/MARKER
    try:
        protected_tree(path,recursive=False)
        if path.stat().st_nlink!=1:raise PermissionError('Recovery marker hardlink rejected')
        with path.open('rb') as stream:old=stream.read(MESSAGE.size+1)
    except FileNotFoundError:
        ProtectedFiles().write(path,raw)
    else:
        if len(old)!=MESSAGE.size:raise ValueError('Invalid recovery marker size')
        magic,reason,device=MESSAGE.unpack(old)
        if magic!=b'GDS1' or device.decode('ascii')!=agent.config['device_id'] or reason not in (225,226):
            raise ValueError('Invalid existing recovery security hold')
    return True
