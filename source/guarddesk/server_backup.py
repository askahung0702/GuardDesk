"""Consistent SQLite snapshot; no agent credentials or server private keys."""
import hashlib
import sqlite3
from contextlib import closing
from pathlib import Path


def purge_stamp(source):
    with closing(sqlite3.connect(Path(source).as_uri()+'?mode=ro',uri=True,timeout=5)) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name='endpoint_purges'").fetchone():return 0
        if db.execute("SELECT 1 FROM endpoint_purges WHERE state<>'completed' LIMIT 1").fetchone():raise ValueError('端點資料清除中，完成後再備份／搬移中心')
        row=db.execute('SELECT rowid FROM endpoint_purges ORDER BY rowid DESC LIMIT 1').fetchone()
        return row[0] if row else 0


def snapshot(source,target,migration=False):
    source=Path(source).resolve();target=Path(target).resolve()
    if not source.is_file():raise ValueError('管理中心資料庫不存在')
    if source==target:raise ValueError('來源與備份不能相同')
    if not target.parent.is_dir():raise ValueError('請先建立並限制備份目錄的存取權限')
    deletion_stamp=purge_stamp(source)
    with target.open('xb'):pass
    try:
        with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True,timeout=15)) as original,closing(sqlite3.connect(target)) as copy:
            original.backup(copy,pages=128,sleep=.01)
            if copy.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise OSError('備份完整性檢查失敗')
            tables={r[0] for r in copy.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {'devices','users','policies'}.issubset(tables) or not ({'events','events_legacy'}&tables):raise ValueError('來源不是管理中心資料庫')
            if migration:
                if 'endpoint_removals' in tables:
                    if copy.execute("SELECT 1 FROM endpoint_removals WHERE status IN ('running','failed') LIMIT 1").fetchone():raise ValueError('請先完成／處理已開始的端點移除工作再搬移管理中心')
                    copy.execute("UPDATE endpoint_removals SET status='expired' WHERE status='queued'")
                copy.execute('DELETE FROM sessions');copy.execute('UPDATE enrollments SET used=1')
                if 'deployment_codes' in tables:copy.execute('UPDATE deployment_codes SET revoked=1')
                if 'update_jobs' in tables:
                    if copy.execute("SELECT 1 FROM update_status s JOIN update_jobs j ON j.id=s.job_id WHERE j.status='pending' AND s.state IN ('applying','restarting') LIMIT 1").fetchone():raise ValueError('請先完成或回復正在切換的 Agent 更新，再搬移中心')
                    copy.execute("UPDATE update_jobs SET status='cancelled' WHERE status='pending'")
                if 'update_presence' in tables:copy.execute('DELETE FROM update_presence')
                if 'remote_sessions' in tables:copy.execute("UPDATE remote_sessions SET status='closed',ended_reason='server_migration' WHERE status IN ('requested','active')")
                if 'remote_presence' in tables:copy.execute('DELETE FROM remote_presence')
                copy.commit()
        from .event_storage import snapshot_days
        event_days=snapshot_days(source,target)
        if purge_stamp(source)!=deletion_stamp:raise ValueError('備份期間有永久刪除，這份副本無效，請在清除完成後重新備份')
        with target.open('rb') as stream:sha=hashlib.file_digest(stream,'sha256').hexdigest()
        return {'event_day_files':event_days,'path':str(target),'sha256':sha,'migration':bool(migration),'credentials_and_audit_database':True,'source_modified':False}
    except BaseException:
        target.unlink(missing_ok=True);raise
