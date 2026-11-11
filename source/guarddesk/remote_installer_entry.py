"""Interactive installation authority is absent from the resident entry."""
import argparse
import json
import sys
from . import remote_trial

INSTALLER_COMMANDS=frozenset({'component-info','endpoint-setup','endpoint-uninstall',
    'usb-install','endpoint-native-install'})

def main(argv=None):
    args=list(sys.argv[1:] if argv is None else argv)
    if not remote_trial.enabled():raise PermissionError('Compiled remote-only installer required')
    if not args or args[0] not in INSTALLER_COMMANDS:
        raise PermissionError('Command is not part of the dedicated remote installer')
    parser=argparse.ArgumentParser(description='GuardDesk remote-only internal installer',allow_abbrev=False)
    sub=parser.add_subparsers(dest='command',required=True)
    def command(name):return sub.add_parser(name,allow_abbrev=False)
    command('component-info');command('endpoint-uninstall')
    endpoint=command('endpoint-setup');endpoint.add_argument('--connection',required=True)
    endpoint.add_argument('--upgrade-existing',action='store_true',help='Explicit same-identity upgrade of this live remote trial')
    install=command('usb-install');install.add_argument('--config',required=True)
    install.add_argument('--action',choices=['Install','Uninstall','Status'],default='Install')
    native=command('endpoint-native-install');native.add_argument('--config',required=True)
    native.add_argument('--action',choices=['Install','Uninstall','Status'],required=True)
    native.add_argument('--diagnostic-pipe',required=True)
    parsed=parser.parse_args(args)
    for stream in (sys.stdout,sys.stderr):
        if stream and hasattr(stream,'reconfigure'):stream.reconfigure(encoding='utf-8')
    if parsed.command=='component-info':
        from . import __version__
        result={'version':__version__,'architecture':'windows-x64','build_role':'remote-installer',
                'install_profile':remote_trial.PROFILE}
    elif parsed.command=='endpoint-setup':
        from .endpoint_setup import install
        result=install(parsed.connection,upgrade_existing=True) if parsed.upgrade_existing else install(parsed.connection)
    elif parsed.command=='endpoint-uninstall':
        from .endpoint_setup import uninstall
        result=uninstall()
    elif parsed.command=='usb-install':
        from .usb_install import install
        result=install(parsed.config,parsed.action)
    else:
        from .usb_install import helper
        raise SystemExit(helper(parsed.config,parsed.action,parsed.diagnostic_pipe))
    print(json.dumps(result,ensure_ascii=False,indent=2))

