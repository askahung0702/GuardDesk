"""Auditable endpoint/center separation, not an antivirus exception or filter.

Shared installer and fixed remote roles still need distinct privilege artifacts;
do not describe payload separation as a completed minimal privileged broker.
"""
FORBIDDEN_MODULES=frozenset({
    'guarddesk.__main__','guarddesk.server','guarddesk.server_setup',
    'guarddesk.server_config','guarddesk.server_backup','guarddesk.storage_maintenance',
    'guarddesk.remote_viewer','guarddesk.mis_onefile','guarddesk.mis_native_media',
    'guarddesk.mis_native_loader',
    'guarddesk.agent','guarddesk.native_usb','guarddesk.application_control',
    'guarddesk.windows_controls',
    'guarddesk.store','guarddesk.deployment','guarddesk.bundled_release',
    'guarddesk.remote','guarddesk.removal','guarddesk.management',
    'guarddesk.audit_archive','guarddesk.audit_reports','guarddesk.audit_search_index',
    'guarddesk.audit_sort','guarddesk.event_storage','guarddesk.endpoint_purge',
    'guarddesk.mail_reports','guarddesk.updates','guarddesk.update_progress',
    'guarddesk.updater_maintenance','guarddesk.browser_auto_publication',
    'guarddesk.browser_publication','guarddesk.browser_release','guarddesk.mis_support',
    'guarddesk.category_library','guarddesk.custom_client','guarddesk.custom_settings',
    'guarddesk.custom_library','guarddesk.custom_network','guarddesk.custom_windows',
    'guarddesk.document_audit','guarddesk.document_settings','guarddesk.file_access',
    'guarddesk.windows_watch','guarddesk.windows_events','guarddesk.upload_proxy','guarddesk.web_upload',
})
FORBIDDEN_PREFIXES=('guarddesk/static/','guarddesk/windows/','browser-extension/')


def deployment_scope(version):
    from guarddesk.release_scope import validate
    return validate({'format':1,'version':version,'scope':'endpoint',
        'components':['native','main'],'min_compatible_agent':'0.4.12',
        'required_updater':None},version)


RUNTIME_FORBIDDEN=frozenset({'guarddesk.endpoint_setup','guarddesk.usb_install',
    'guarddesk.native_installer','guarddesk.remote_installer_entry','guarddesk.installer_channel',
    'guarddesk.remote_test_install'})

def check_inventory(modules,files,*,installer=False):
    unexpected=(FORBIDDEN_MODULES | (set() if installer else RUNTIME_FORBIDDEN)).intersection(modules)
    if unexpected:raise ValueError('Center/viewer modules included in endpoint: '+','.join(sorted(unexpected)))
    required={'guarddesk.remote_trial','guarddesk.endpoint_files',
              'guarddesk.remote_endpoint_state','guarddesk.endpoint_transport','guarddesk.windows_privilege',
              'guarddesk.machine_agent','guarddesk.windows_sessions',
              'guarddesk.machine_agent_session','guarddesk.remote_native_broker'}
    required|=({'guarddesk.remote_installer_entry','guarddesk.endpoint_setup','guarddesk.native_installer'}
               if installer else {'guarddesk.remote_endpoint_entry','guarddesk.remote_service_worker'})
    if not required.issubset(modules):raise ValueError('Required endpoint modules missing: '+','.join(sorted(required-set(modules))))
    for name in files:
        name=name.replace('\\','/')
        inner=name.removeprefix('_internal/')
        if (inner.startswith(FORBIDDEN_PREFIXES) or name.lower().endswith(('.ps1','.psm1'))
            or inner in {'GuardDeskMIS.exe','GuardDeskRemote.exe','remote/GuardDeskMisNative.dll'}):
            raise ValueError('Non-endpoint payload included: '+name)

