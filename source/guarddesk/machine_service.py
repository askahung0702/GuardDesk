"""Build-time full Agent SCM integration, never an endpoint policy toggle."""
from pathlib import Path

ENABLED = False

def enabled():return ENABLED is True

def image(executable):
    from .remote_trial import enabled as trial
    root=Path(executable).parent
    return root/'_internal/GuardDeskService.exe' if enabled() and not trial() else root/'GuardDeskService.exe'

def worker(config,stop):
    if not enabled():raise PermissionError('Full machine service is not enabled in this build')
    from .remote_trial_install import check_settings
    from .native_installer import read_json
    check_settings(read_json(config))
    from .native_usb import UsbWorker
    from .machine_agent import eligible
    native=UsbWorker(config)
    if not eligible(native.agent):raise PermissionError('Full service worker requires the protected installed image and configuration')
    return native.run(stop,extended=True)
