"""Development workflow guard only. Never bundled into endpoint authority."""
from pathlib import Path
import json

def require_center_test_host(workspace):
    path=Path(workspace)/'DEVELOPMENT-HOST-POLICY.json'
    if not path.exists():return
    if path.is_symlink() or path.stat().st_size>8192:raise PermissionError('Invalid development-host policy; no local center started')
    body=json.loads(path.read_text(encoding='utf-8-sig'))
    if body.get('role')=='development-workstation' and body.get('local_management_center')!='enabled':
        raise PermissionError('User disabled local management centers on this development checkout. Run integration acceptance on the external Server; no localhost fixture may be created.')
