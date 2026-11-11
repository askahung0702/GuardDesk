"""Dedicated remote endpoint CLI; never dispatch through the center CLI."""
import argparse
import json
import logging
import signal
import sys
import threading
from . import remote_trial

ENDPOINT_COMMANDS=frozenset({'component-info','usb-worker','remote-service-worker',
    'machine-session','remote-admin-session'})


def main(argv=None):
    args=list(sys.argv[1:] if argv is None else argv)
    if not remote_trial.enabled():
        raise PermissionError('Dedicated remote endpoint requires a compiled remote-only build')
    if not args or args[0] not in ENDPOINT_COMMANDS:
        raise PermissionError('Command is not part of the dedicated remote endpoint')
    parser=argparse.ArgumentParser(description='GuardDesk remote-only internal endpoint',allow_abbrev=False)
    sub=parser.add_subparsers(dest='command',required=True)
    def command(name):return sub.add_parser(name,allow_abbrev=False)
    command('component-info')
    command('machine-session').add_argument('--parent',type=int,required=True)
    admin=command('remote-admin-session')
    admin.add_argument('--device-id',required=True);admin.add_argument('--session-id',required=True)
    service=command('remote-service-worker')
    service.add_argument('--device-id',required=True)
    service.add_argument('--stop-handle',type=int,required=True)
    worker=command('usb-worker')
    worker.add_argument('--config',required=True)
    worker.add_argument('--once',action='store_true');worker.add_argument('--restore',action='store_true')
    # Existing installer argv uses this flag. The dedicated worker still calls
    # only remote_trial.worker; this never enables ExtendedWorker or controls.
    worker.add_argument('--extended',action='store_true')
    parsed=parser.parse_args(args)
    if parsed.command=='component-info':
        from . import __version__
        print(json.dumps({'version':__version__,'update_protocol':1,'architecture':'windows-x64',
                         'build_role':'remote-endpoint','install_profile':remote_trial.PROFILE}))
        return
    for stream in (sys.stdout,sys.stderr):
        if stream and hasattr(stream,'reconfigure'):stream.reconfigure(encoding='utf-8')
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
    stop=threading.Event()
    signal.signal(signal.SIGINT,lambda *_:stop.set())
    if parsed.command=='machine-session':
        from .machine_agent_session import run
        return run(parsed.parent,stop)
    elif parsed.command=='remote-admin-session':
        from .remote_admin_windows import run
        return run(parsed.device_id,parsed.session_id,stop)
    elif parsed.command=='remote-service-worker':
        from .remote_service_worker import run
        return run(parsed.device_id,parsed.stop_handle,stop)
    elif parsed.command=='usb-worker':
        result=remote_trial.worker(parsed.config,stop,once=parsed.once,restore=parsed.restore)
        if result is not None:print(json.dumps(result,ensure_ascii=False))
