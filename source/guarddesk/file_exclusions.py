"""Pure path filters shared by native audit and bounded fallback scans."""
import ntpath
import os
import re
from functools import lru_cache

# Reserved rule in the existing exclude_paths list. Older Agents accept the
# policy unchanged; the management center also enforces this rule on arrival.
DEVELOPMENT_RULE='@guarddesk:development-cache:v1'
DEVELOPMENT_DIRECTORIES=frozenset((
    'node_modules','.git','.venv','.tox','.nox','__pycache__',
    '.pytest_cache','.mypy_cache','.ruff_cache','.gradle','.vs',
))


def development_path(path):
    """Metadata-only classification; never guess from file extensions/content."""
    parts=normalized_path(path).split('\\')
    if any(part in DEVELOPMENT_DIRECTORIES for part in parts):return True
    joined='\\'+'\\'.join(parts)+'\\'
    return any(marker in joined for marker in (
        '\\.cache\\pip\\','\\.npm\\_cacache\\','\\.nuget\\packages\\',
        '\\.cargo\\registry\\','\\appdata\\local\\pip\\cache\\',
        '\\appdata\\local\\npm-cache\\',
    ))


@lru_cache(maxsize=256)
def user_path_template(rule):
    """One explicit whole-directory token; no globbing or environment lookup."""
    raw=rule.replace('/','\\').lower()
    if raw.startswith(('\\\\?\\','\\??\\')):raw=raw[4:]
    parts=raw.rstrip('\\').split('\\')
    if len(parts)<3 or not re.fullmatch(r'[a-z]:',parts[0]) or parts.count('{user}')!=1:return None
    # Require a literal profile-parent directory before the token. Validate
    # before normpath so token/.. can never broaden an exclusion silently.
    if parts.index('{user}')<2:return None
    for part in parts[1:]:
        if part=='{user}':continue
        if not part or part in ('.','..') or any(c in part for c in '*?%{}:<>"|') or any(ord(c)<32 for c in part):return None
    return tuple(parts)


def validate_user_path_rules(rules):
    for rule in rules:
        if rule.startswith('@guarddesk:hidden-files:') and rule!='@guarddesk:hidden-files:v1':
            raise ValueError('隱藏檔排除設定版本或格式不正確')
        if '{user}' in rule.casefold() and user_path_template(rule) is None:
            raise ValueError('使用者路徑請使用 C:\\Users\\{user}\\資料夾；{user} 僅可出現一次且須為完整目錄，不支援萬用字元、環境變數或 ..')


def matches_extra(path,extra):
    p=normalized_path(path)
    for rule in extra:
        if rule==DEVELOPMENT_RULE:
            if development_path(p):return True
        elif rule=='@guarddesk:hidden-files:v1':
            # This function is also used by Server ingestion: never inspect a
            # remote endpoint path on the Server's own filesystem.
            continue
        elif '{user}' in rule.casefold():
            template=user_path_template(rule)
            parts=p.split('\\')
            if template and len(parts)>=len(template) and all(
                (bool(actual) and actual not in ('.','..')) if expected=='{user}' else actual==expected
                for actual,expected in zip(parts,template)):
                return True
        elif p==normalized_path(rule) or p.startswith(normalized_path(rule).rstrip('\\')+'\\'):
            return True
    return False


FILE_ACTIVITY_KINDS=frozenset(('file.created','file.deleted','file.opened','file.web_handoff',
    'file.copy_candidate','file.open_requested','file.delete_requested','file.renamed','file.moved',
    'file.rename_from','file.rename_to'))


def excluded_activity(kind,details,extra):
    """Filter ordinary file activity, preserving security and boundary crossings."""
    if kind not in FILE_ACTIVITY_KINDS or not extra:return False
    paths=[details[k] for k in ('path','source_path','destination_path') if k in details]
    # An incomplete rename/move must remain visible, not be mistaken for an
    # operation entirely within an excluded directory.
    if kind in ('file.renamed','file.moved') and not all(details.get(k) for k in ('source_path','destination_path')):return False
    return bool(paths) and all(isinstance(p,str) and p and matches_extra(p,extra) for p in paths)


def normalized_path(path):
    result=ntpath.normcase(ntpath.normpath(path))
    if result.startswith(('\\\\?\\','\\??\\')) and len(result)>6 and result[4] in 'abcdefghijklmnopqrstuvwxyz' and result[5]==':':
        result=result[4:]
    return result


def internal_health_path(path):
    """Only the broker's two fixed health files, never a basename wildcard."""
    if not isinstance(path,str) or not path:return False
    p=normalized_path(path)
    # Standard ProgramData can be on another volume. A locally relocated
    # ProgramData is also recognized by endpoint collectors, without scanning.
    roots=[normalized_path(os.environ.get('ProgramData',r'C:\ProgramData'))]
    drive,tail=ntpath.splitdrive(p)
    if re.fullmatch(r'[a-z]:',drive):roots.append(drive+r'\programdata')
    for root in roots:
        prefix=root.rstrip('\\')+r'\guarddeskpilot\usbcontrol'+'\\'
        if p.startswith(prefix) and re.fullmatch(r'[0-9a-f]{24}\\broker-health\.(?:json|new)',p[len(prefix):]):return True
        if p.startswith(prefix) and re.fullmatch(r'[0-9a-f]{24}\\customsettings\\network-lease\.(?:json|new)',p[len(prefix):]):return True
        if p.startswith(prefix) and re.fullmatch(r'[0-9a-f]{24}\\website-policy-(?:chrome|edge)\.(?:json|new)',p[len(prefix):]):return True
        if p.startswith(prefix) and re.fullmatch(r'[0-9a-f]{24}\\website-policy\.lock',p[len(prefix):]):return True
        if p.startswith(prefix) and re.fullmatch(r'[0-9a-f]{24}\\updates\\(?:transaction-native|updater-refresh)\.json\.state\.(?:json|new)',p[len(prefix):]):return True
        if p.startswith(prefix) and re.fullmatch(r'[0-9a-f]{24}\\updates\\last-update-failure-(?:native|main)\.(?:json|new)',p[len(prefix):]):return True
        if p.startswith(prefix) and re.fullmatch(r'[0-9a-f]{24}\\updates\\[0-9a-f]{32}\\cache-receipt\.(?:json|new)',p[len(prefix):]):return True
    return False


def excluded_internal_health_activity(kind,severity,details):
    """Suppress informational internal churn; preserve alerts and crossings."""
    if severity!='info' or kind not in FILE_ACTIVITY_KINDS:return False
    if kind in ('file.renamed','file.moved') and not all(details.get(k) for k in ('source_path','destination_path')):return False
    paths=[details[k] for k in ('path','source_path','destination_path') if k in details]
    return bool(paths) and all(internal_health_path(p) for p in paths)


def installer_rollback_path(path):
    if not isinstance(path,str) or not path:return False
    drive,tail=ntpath.splitdrive(normalized_path(path))
    return bool(re.fullmatch('[a-z]:',drive) and tail.startswith('\\') and tail.lstrip('\\').split('\\',1)[0]=='config.msi')


def excluded_installer_activity(kind,severity,details):
    """Exact volume-root Installer scratch only; retain alerts and crossings."""
    if kind not in FILE_ACTIVITY_KINDS or severity=='critical':return False
    if kind in ('file.renamed','file.moved') and not all(details.get(k) for k in ('source_path','destination_path')):return False
    paths=[details[k] for k in ('path','source_path','destination_path') if k in details]
    return bool(paths) and all(installer_rollback_path(p) for p in paths)


def profile_hive(path):
    """Known profile hives only; same-named documents elsewhere remain audited."""
    parent,name=ntpath.split(path)
    base='ntuser.dat' if name.startswith('ntuser.dat') else 'usrclass.dat' if name.startswith('usrclass.dat') else None
    if not base:return False
    if name not in (base,base+'.log',base+'.log1',base+'.log2'):
        guid=r'\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}'
        if not re.fullmatch(re.escape(base)+guid+r'\.tm(?:\.blf|container[0-9]{1,20}\.regtrans-ms)',name):return False
    if base=='usrclass.dat':
        suffix=r'\appdata\local\microsoft\windows'
        if not parent.endswith(suffix):return False
        parent=parent[:-len(suffix)]
    profiles=normalized_path(ntpath.dirname(os.environ.get('PUBLIC',r'C:\Users\Public')))
    current=normalized_path(os.environ['USERPROFILE']) if os.environ.get('USERPROFILE') else None
    return bool(parent==current or ntpath.dirname(parent)==profiles)


def excluded(path, extra=(), runtime=None):
    p=normalized_path(path)
    if internal_health_path(p):return True
    if matches_extra(p,extra):return True
    if installer_rollback_path(p):return True
    system=os.environ.get('SystemRoot',r'C:\Windows')
    defaults=[system,r'C:\$Recycle.Bin',r'C:\System Volume Information']
    defaults += [os.environ.get('ProgramFiles',r'C:\Program Files'),os.environ.get('ProgramFiles(x86)',r'C:\Program Files (x86)')]
    defaults += [str(runtime)] if runtime else []
    if any(p==normalized_path(d) or p.startswith(normalized_path(d).rstrip('\\')+'\\') for d in defaults):
        return True
    if any(part in ('$recycle.bin','system volume information') for part in p.split('\\')):
        return True
    startup=r'\start menu\programs\startup'
    if p.endswith(startup) or startup+'\\' in p or ntpath.basename(p) in ('pagefile.sys','swapfile.sys','hiberfil.sys','bootmgr','bootnxt'):
        return True
    if profile_hive(p):return True
    drive,tail=ntpath.splitdrive(p)
    # Boot assets live at the volume root. A user's Documents\Boot folder
    # is not a system directory merely because it shares the same name.
    if len(drive)==2 and drive[1]==':' and tail.lstrip('\\').split('\\',1)[0] in ('boot','efi','recovery'):return True
    if '@guarddesk:hidden-files:v1' in extra:
        from .hidden_files import hidden
        return hidden(p)
    return False


