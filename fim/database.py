"""SQLite persistence for FIM baseline, change history, and scan stats."""

import json
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from .models import ChangeEvent, FileMetadata


class DatabaseManager:
    """Thread-safe SQLite wrapper for FIM state."""

    def __init__(self, db_path: str = "fim_database.db"):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None
        self.lock = threading.Lock()
        self._initialize_db()

    def _initialize_db(self) -> None:
        with self.lock:
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
            cursor = self.conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS baseline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT UNIQUE NOT NULL,
                    hash TEXT NOT NULL,
                    size INTEGER,
                    modified_time REAL,
                    created_time REAL,
                    permissions TEXT,
                    owner TEXT,
                    inode INTEGER,
                    last_scanned TEXT,
                    watch_directory TEXT
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_path ON baseline (file_path)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_watch_dir ON baseline (watch_directory)')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS change_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    old_hash TEXT,
                    new_hash TEXT,
                    old_size INTEGER,
                    new_size INTEGER,
                    severity TEXT,
                    details TEXT
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON change_history (timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_type ON change_history (event_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_path_history ON change_history (file_path)')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_timestamp TEXT NOT NULL,
                    directory TEXT NOT NULL,
                    files_scanned INTEGER,
                    changes_detected INTEGER,
                    duration_seconds REAL,
                    cpu_usage REAL,
                    memory_usage_mb REAL
                )
            ''')
            self.conn.commit()

    def save_baseline(self, file_metadata: FileMetadata, watch_directory: str) -> None:
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO baseline
                (file_path, hash, size, modified_time, created_time, permissions,
                 owner, inode, last_scanned, watch_directory)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                file_metadata.path,
                file_metadata.hash,
                file_metadata.size,
                file_metadata.modified_time,
                file_metadata.created_time,
                file_metadata.permissions,
                file_metadata.owner,
                file_metadata.inode,
                datetime.now().isoformat(),
                watch_directory,
            ))
            self.conn.commit()

    def save_baseline_batch(self, items, watch_directory: str) -> None:
        """Bulk insert/replace many FileMetadata rows in a single transaction.

        Order-of-magnitude faster than calling ``save_baseline`` in a loop
        because all rows share one fsync at commit time.
        """
        now = datetime.now().isoformat()
        rows = [
            (m.path, m.hash, m.size, m.modified_time, m.created_time,
             m.permissions, m.owner, m.inode, now, watch_directory)
            for m in items
        ]
        if not rows:
            return
        with self.lock:
            cursor = self.conn.cursor()
            cursor.executemany('''
                INSERT OR REPLACE INTO baseline
                (file_path, hash, size, modified_time, created_time, permissions,
                 owner, inode, last_scanned, watch_directory)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', rows)
            self.conn.commit()

    def save_changes_batch(self, events) -> None:
        """Bulk insert change events in a single transaction."""
        rows = [
            (e.timestamp, e.event_type, e.file_path, e.old_hash, e.new_hash,
             e.old_size, e.new_size, e.severity,
             json.dumps(e.details) if e.details else None)
            for e in events
        ]
        if not rows:
            return
        with self.lock:
            cursor = self.conn.cursor()
            cursor.executemany('''
                INSERT INTO change_history
                (timestamp, event_type, file_path, old_hash, new_hash,
                 old_size, new_size, severity, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', rows)
            self.conn.commit()

    def get_baseline(self, watch_directory: Optional[str] = None) -> Dict[str, FileMetadata]:
        with self.lock:
            cursor = self.conn.cursor()
            if watch_directory:
                cursor.execute(
                    'SELECT * FROM baseline WHERE watch_directory = ?',
                    (watch_directory,))
            else:
                cursor.execute('SELECT * FROM baseline')

            baseline: Dict[str, FileMetadata] = {}
            for row in cursor.fetchall():
                metadata = FileMetadata(
                    path=row['file_path'],
                    hash=row['hash'],
                    size=row['size'],
                    modified_time=row['modified_time'],
                    created_time=row['created_time'],
                    permissions=row['permissions'],
                    owner=row['owner'],
                    inode=row['inode'],
                )
                baseline[row['file_path']] = metadata
            return baseline

    def save_change(self, event: ChangeEvent) -> None:
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO change_history
                (timestamp, event_type, file_path, old_hash, new_hash,
                 old_size, new_size, severity, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.timestamp,
                event.event_type,
                event.file_path,
                event.old_hash,
                event.new_hash,
                event.old_size,
                event.new_size,
                event.severity,
                json.dumps(event.details) if event.details else None,
            ))
            self.conn.commit()

    def save_scan_stats(self, directory: str, files_scanned: int,
                        changes_detected: int, duration: float,
                        cpu_usage: float = 0.0, memory_usage: float = 0.0) -> None:
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO scan_statistics
                (scan_timestamp, directory, files_scanned, changes_detected,
                 duration_seconds, cpu_usage, memory_usage_mb)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                directory,
                files_scanned,
                changes_detected,
                duration,
                cpu_usage,
                memory_usage,
            ))
            self.conn.commit()

    def delete_baseline_entry(self, file_path: str) -> None:
        with self.lock:
            cursor = self.conn.cursor()
            cursor.execute('DELETE FROM baseline WHERE file_path = ?', (file_path,))
            self.conn.commit()

    def get_change_history(self, hours: int = 24,
                           event_type: Optional[str] = None) -> List[Dict]:
        with self.lock:
            cursor = self.conn.cursor()
            cutoff_time = (datetime.now() - timedelta(hours=hours)).isoformat()
            if event_type:
                cursor.execute('''
                    SELECT * FROM change_history
                    WHERE timestamp > ? AND event_type = ?
                    ORDER BY timestamp DESC
                ''', (cutoff_time, event_type))
            else:
                cursor.execute('''
                    SELECT * FROM change_history
                    WHERE timestamp > ?
                    ORDER BY timestamp DESC
                ''', (cutoff_time,))
            return [dict(row) for row in cursor.fetchall()]

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None
