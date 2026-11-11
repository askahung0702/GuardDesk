"""Server-side field inheritance; endpoint packets remain complete policies."""
import copy
from .policy import DEFAULT_POLICY, validate_policy


PATHS = {key for key, value in DEFAULT_POLICY.items() if not isinstance(value, dict)}
PATHS |= {key + '.' + child for key, value in DEFAULT_POLICY.items() if isinstance(value, dict) for child in value}
APPEND_PATHS = {'file_audit.exclude_paths', 'application_audit_exclusions'}


def get_value(body, path):
    value = body
    for part in path.split('.'):
        value = value[part]
    return value


def put_value(body, path, value):
    parts = path.split('.')
    target = body
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = copy.deepcopy(value)


def apply_operations(body, operations, validate=True):
    result = copy.deepcopy(body)
    for item in operations:
        value = item['value']
        if item['op'] == 'append':
            value = list(get_value(result, item['path']))
            seen = {v.casefold() for v in value}
            for candidate in item['value']:
                if candidate.casefold() not in seen:
                    seen.add(candidate.casefold())
                    value.append(candidate)
        put_value(result, item['path'], value)
    if validate:validate_policy(result)
    return result


def validate_operations(operations, overrides=None):
    if not isinstance(operations, list) or len(operations) > len(PATHS):
        raise ValueError('欄位設定數量不正確')
    seen = set()
    for item in operations:
        if not isinstance(item, dict) or set(item) != {'path', 'op', 'value'}:
            raise ValueError('欄位設定結構不正確')
        path = item['path']
        if not isinstance(path, str) or path not in PATHS or path in seen:
            raise ValueError('欄位不存在或重複')
        seen.add(path)
        if item['op'] not in ('set', 'append') or (item['op'] == 'append' and path not in APPEND_PATHS):
            raise ValueError('此欄位不支援追加')
        if path.split('.')[0] in (overrides or {}):
            raise ValueError('同一模組不可同時使用整組覆寫與欄位設定')
        if item['op'] == 'append' and (not isinstance(item['value'], list) or any(not isinstance(v, str) for v in item['value'])):
            raise ValueError('追加清單不正確')
    apply_operations({**copy.deepcopy(DEFAULT_POLICY), **copy.deepcopy(overrides or {})}, operations)
    return copy.deepcopy(operations)


def policy_keys(policy):
    return set(policy['overrides']) | {item['path'].split('.')[0] for item in policy.get('operations', [])}
