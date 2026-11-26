"""Policy for ordinary browser visits, file-upload evidence and process stops."""
from urllib.parse import urlsplit
from .serialization import canonical, digest

FIELDS = {
    'browser_visit_detail': 'domain',
    'browser_upload_mode': 'follow',
    'application_stop_mode': 'all',
    'application_stop_programs': [],
}


def uploads_enabled(policy):
    mode = policy.get('browser_upload_mode', 'follow')
    return policy['browser_audit'] if mode == 'follow' else mode == 'enabled'


def uploads_enabled_for_device(policy, plane, device):
    if uploads_enabled(policy):
        return True
    if not any(a['enabled'] and a['target_type'] == 'user' for a in plane.assignments):
        return False
    return any(uploads_enabled(item['body']) for item in plane.bundle(device)['user_policies'].values())


def browser_account(kind, details):
    account = details.get('user')
    if kind == 'file.web_handoff':
        account = details.get('reporting_account') or account
    return account.casefold() if isinstance(account, str) else None


def validate(policy):
    from .application_exclusions import validate_exclusions
    if policy['browser_visit_detail'] not in ('domain', 'detailed'):
        raise ValueError('瀏覽紀錄請選擇網域或詳細網址')
    if policy['browser_upload_mode'] not in ('follow', 'enabled', 'disabled'):
        raise ValueError('網站檔案上傳稽核設定不正確')
    if policy['application_stop_mode'] not in ('all', 'selected'):
        raise ValueError('程式停止稽核設定不正確')
    validate_exclusions(policy['application_stop_programs'], allow_directories=False)


def stop_signature(policy):
    return digest(canonical([policy.get('application_stop_mode', 'all'), policy.get('application_stop_programs', [])]))


def excluded_stop(kind, severity, details, policy):
    if kind != 'application.stopped' or severity != 'info' or policy.get('application_stop_mode') != 'selected':
        return False
    from .application_exclusions import excluded_application
    # Match the same exact names / paths as the existing start-and-stop list.
    return not excluded_application(kind, severity, details, policy['application_stop_programs'])


def browser_kind(kind):
    return kind in ('web.navigation', 'web.page_title', 'file.web_handoff') or kind.startswith('web.upload_')


def browser_details(kind, details, policy):
    """Apply before local enqueue, before retry and at central ingestion."""
    if kind == 'web.upload_gap':
        if details.get('reason') == 'request_body_unavailable':
            return None
        if not uploads_enabled(policy):
            # Keep evidence of an earlier collection loss without sending the URL.
            fields = ('source', 'reason', 'lost_count', 'user', 'browser', 'reporting_account', 'user_session_id')
            return {key: details[key] for key in fields if key in details}
    if kind not in ('web.navigation', 'web.page_title'):
        return details if uploads_enabled(policy) else None
    if not policy['browser_audit'] or kind == 'web.page_title' or details.get('source') == 'browser_extension':
        return None
    if policy.get('browser_visit_detail') == 'detailed':
        return details
    return domain_visit(details)


def domain_visit(details):
    raw = details.get('url') or details.get('domain')
    if not isinstance(raw, str) or not raw:
        return None
    try:
        # Accept the hostname directly for new agents, or derive it from a legacy URL.
        if details.get('url'):
            parsed = urlsplit(raw)
            if parsed.scheme not in ('http', 'https'):
                return None
            domain = parsed.hostname
        else:
            domain = raw
        if not domain or len(domain) > 253 or any(c.isspace() or c in '/\\@?#%' or ord(c) < 32 for c in domain):
            return None
        if ':' in domain:
            from ipaddress import IPv6Address
            domain = str(IPv6Address(domain))
        elif not all(part and len(part) <= 63 and all(c.isalnum() or c in '-_' for c in part)
                     for part in domain.rstrip('.').split('.')):
            return None
    except ValueError:
        return None
    fields = ('user', 'browser', 'source', 'coverage', 'reporting_account', 'user_session_id', 'collection_scope', 'clock_warning')
    return {**{key: details[key] for key in fields if key in details}, 'domain': domain.lower()}


def domain_visit_id(device_id, occurred, details):
    """A domain-only saved visit represents one second of activity on this endpoint."""
    if (not device_id or details.get('source') != 'browser_history' or details.get('coverage') != 'saved_visit'
            or any(key in details for key in ('url', 'title', 'visit_id', 'profile'))
            or not all(isinstance(details.get(key), str) and details[key] for key in ('user', 'browser', 'domain'))):
        return None
    scope = {**details, 'user': details['user'].casefold(), 'browser': details['browser'].casefold(),
             'domain': details['domain'].lower()}
    return 'domain-visit-' + digest(canonical([device_id, int(occurred), scope]))
