"""Explicit LAB01 in-place lab entry. No enrollment, cleanup or retargeting."""
import json
import platform
from pathlib import Path
import re
import sys


def target():
    from .remote_trial import enabled
    if enabled():raise ValueError('LAB01 existing standard Agent requires the standard test candidate')
    if platform.node().split('.')[0].casefold()!='lab01':
        raise ValueError('This entry is for the authorized LAB01 test only; no changes made')


def existing():
    from .machine_agent_session import discover
    from .update_native import folder
    # Use the existing authenticated, token-free public status IPC first.
    # A standard user need not read protected ProgramData before approving UAC.
    target();marker=discover()
    if not marker or marker.get('scope')!='machine' or marker.get('install_profile','standard')!='standard':
        raise ValueError('Existing machine-wide standard Agent required; enrollment/uninstall not performed')
    did=marker.get('device_id')
    if not isinstance(did,str) or not re.fullmatch('[0-9a-f]{24}',did):raise ValueError('Invalid existing machine identity')
    return marker,folder(35)/'USBControl'/did/'config.json'


def preflight(config,settings,source,*,staging=False):
    """Called elevated before transaction mutation, for both check/install."""
    from .update_native import protected_tree
    from .native_installer import assert_quiescent
    from .agent import request
    from .update_packages import version
    from .remote_components import read_cohort
    marker,expected=existing()
    from . import __version__
    if version(marker['version'])>version(__version__):
        raise ValueError('Installed Agent is newer than this candidate; no downgrade performed')
    if Path(config).resolve()!=expected.resolve():raise ValueError('Original protected machine configuration required')
    protected_tree(expected,recursive=False)
    if settings.get('install_profile','standard')!='standard' or any(settings.get(k)!=marker.get(k) for k in ('device_id','server')):
        raise ValueError('Existing endpoint profile/identity mismatch; preserve installation')
    assert_quiescent(expected.parent,include_install=not staging)
    read_cohort(source)
    # No Agent construction/SQLite access, endpoint registration, session
    # creation or fake consent. Original token/CA go only to original center.
    reply=request(settings['server'],'/api/agent/remote/test-readiness',{},settings['token'],settings.get('ca'),timeout=5)
    if not isinstance(reply,dict) or reply.get('enabled') is not True or reply.get('wire')!=1 or version(reply.get('version','0'))<version('0.4.79'):
        raise ValueError('Matching 0.4.79+ center with protected native preview opt-in required; original Agent retained')
    if reply.get('update_busy') is not False or reply.get('remote_busy') is not False:
        raise ValueError('Existing center update/remote session is busy; no installation performed')
    return {'check_only':True,'device_id':marker['device_id'],'center_version':reply['version'],
            'existing_version':marker['version'],'registration':'preserved','cleanup_performed':False}


def run(check_only=False):
    from .windows_privilege import is_admin
    from .usb_install import run_native,elevate,InstallError
    if not getattr(sys,'frozen',False):raise ValueError('Use the complete frozen LAB01 test package')
    marker,config=existing();source=Path(sys.executable).resolve().parent
    action='Status' if check_only else 'Install'
    report=(run_native(config,action,source,remote_test=True) if is_admin()
            else elevate(config,action,source,remote_test=True))
    if report['exit_code']:raise InstallError(report)
    return {'result':'CHECK_PASSED' if check_only else 'NATIVE_INSTALLER_COMPLETED',
            'version':__import__('guarddesk').__version__,'device_id':marker['device_id'],
            'registration':'preserved','full_remote_acceptance':False,'formal_release':False}
