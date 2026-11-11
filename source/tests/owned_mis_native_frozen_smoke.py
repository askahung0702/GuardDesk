"""Separate owned frozen test entry, never shipped in the MIS product entry."""
import ctypes
import json
from pathlib import Path
import sys
from guarddesk.mis_native_media import NativeLibrary,Config


def main():
    root=Path(sys._MEIPASS)
    library=NativeLibrary(root)
    config=Config();config.bytes=ctypes.sizeof(config);config.version=1
    config.session[0]=9;config.transport=1;config.consent_deadline=library.tick()+10000
    config.local_count=config.peer_count=1;config.local_ipv4[0]=config.peer_ipv4[0]=0x0100007f
    config.owned_loopback=config.hidden=config.software=1
    handle=library.create(config)
    try:
        library.grant(handle,library.tick()+3000);library.offer(handle)
        signal=library.take_signal(handle)
        assert signal and signal['type']=='offer' and signal['sdp'].startswith('v=0\r\n')
        library.pump(handle)
    finally:
        library.stop(handle);library.close(handle);library.pins.close()
    print(json.dumps({'passed':True,'frozen_extraction_loader':True,'hidden_own_window':True,
        'actual_native_offer':True,'SDP_logged':False,'desktop_capture':False,'os_input':False}))


if __name__=='__main__':main()
