"""Directory walking, file hashing, and metadata extraction."""

import fnmatch
import hashlib
import os
import platform
import threading
import time
from pathlib import Path
from queue import Empty, PriorityQueue, Queue
from typing import Dict, Optional, Tuple, TYPE_CHECKING

from .models import FileMetadata

if TYPE_CHECKING:
    from config import ConfigManager
    from log_handlers import JSONLogger

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


class FileScanner:
    """Owns hashing, metadata extraction, and the multi-threaded directory walk."""

    POISON_PILL = (999, None)

    def __init__(self, config: 'ConfigManager', logger: 'JSONLogger',
                 shutdown_event: threading.Event):
        self.config = config
        self.logger = logger
        self.shutdown_event = shutdown_event

        self.worker_threads = config.get('monitoring.worker_threads', 4)
        self.max_file_size = config.get('monitoring.max_file_size_mb', 500) * 1024 * 1024

        self.enable_caching = config.get('performance.enable_caching', True)
        self.cache: Dict[str, Tuple[str, float, float]] = {} if self.enable_caching else None
        self.cache_ttl = config.get('performance.cache_ttl_seconds', 300)

        self.errors = 0

    # --- Exclusion / priority -----------------------------------------------
    def get_file_priority(self, filepath: str) -> Tuple[int, str]:
        priority_patterns = self.config.get('priority_patterns', {})
        for severity, patterns in priority_patterns.items():
            for pattern in patterns:
                if fnmatch.fnmatch(filepath, pattern) or \
                        fnmatch.fnmatch(os.path.basename(filepath), pattern):
                    priority_map = {
                        'critical': (0, 'critical'),
                        'high': (1, 'high'),
                        'medium': (2, 'medium'),
                    }
                    return priority_map.get(severity, (3, 'low'))
        return (3, 'low')

    def should_exclude(self, filepath: str) -> bool:
        exclude_patterns = self.config.get('exclude_patterns', [])
        for pattern in exclude_patterns:
            if fnmatch.fnmatch(filepath, pattern) or \
                    fnmatch.fnmatch(os.path.basename(filepath), pattern):
                return True
        return False

    # --- Hashing ------------------------------------------------------------
    def calculate_hash(self, filepath: str) -> Optional[str]:
        try:
            file_size = os.path.getsize(filepath)
            if file_size > self.max_file_size:
                self.logger.log_system('warning',
                    f'Skipping large file: {filepath}',
                    size_mb=file_size / (1024 * 1024))
                return None

            if self.enable_caching and filepath in self.cache:
                cached_hash, cached_mtime, cached_time = self.cache[filepath]
                current_mtime = os.path.getmtime(filepath)
                if (cached_mtime == current_mtime and
                        time.time() - cached_time < self.cache_ttl):
                    return cached_hash

            sha256_hash = hashlib.sha256()
            chunk_size = 65536
            with open(filepath, 'rb') as f:
                while chunk := f.read(chunk_size):
                    sha256_hash.update(chunk)

            file_hash = sha256_hash.hexdigest()
            if self.enable_caching:
                self.cache[filepath] = (
                    file_hash, os.path.getmtime(filepath), time.time())
            return file_hash
        except (PermissionError, FileNotFoundError, OSError) as e:
            self.logger.log_system('warning',
                f'Cannot access file: {filepath}', error=str(e))
            return None
        except Exception as e:  # noqa: BLE001
            self.logger.log_system('error',
                f'Unexpected error hashing file: {filepath}', error=str(e))
            self.errors += 1
            return None

    # --- Metadata -----------------------------------------------------------
    def get_file_metadata(self, filepath: str) -> Optional[FileMetadata]:
        try:
            stat_info = os.stat(filepath)
            file_hash = self.calculate_hash(filepath)
            if file_hash is None:
                return None

            permissions = oct(stat_info.st_mode)[-3:]

            try:
                if platform.system() == 'Windows':
                    import win32security  # type: ignore
                    sd = win32security.GetFileSecurity(
                        filepath, win32security.OWNER_SECURITY_INFORMATION)
                    owner_sid = sd.GetSecurityDescriptorOwner()
                    owner = win32security.LookupAccountSid(None, owner_sid)[0]
                else:
                    import pwd
                    owner = pwd.getpwuid(stat_info.st_uid).pw_name
            except Exception:  # noqa: BLE001
                owner = str(getattr(stat_info, 'st_uid', ''))

            return FileMetadata(
                path=filepath,
                hash=file_hash,
                size=stat_info.st_size,
                modified_time=stat_info.st_mtime,
                created_time=stat_info.st_ctime,
                permissions=permissions,
                owner=owner,
                inode=stat_info.st_ino if hasattr(stat_info, 'st_ino') else None,
            )
        except Exception as e:  # noqa: BLE001
            self.logger.log_system('error',
                f'Error getting metadata: {filepath}', error=str(e))
            return None

    # --- Worker -------------------------------------------------------------
    def _scan_file_worker(self, file_queue: PriorityQueue,
                          results_queue: Queue, watch_directory: str) -> None:
        while not self.shutdown_event.is_set():
            try:
                priority, filepath = file_queue.get(timeout=1)
                if filepath is None:  # poison pill
                    file_queue.task_done()
                    break
                if self.should_exclude(filepath):
                    file_queue.task_done()
                    continue

                metadata = self.get_file_metadata(filepath)
                if metadata:
                    relative_path = os.path.relpath(filepath, watch_directory)
                    metadata.path = relative_path
                    results_queue.put((priority, metadata))
                file_queue.task_done()
            except Exception:  # queue.Empty or any worker error
                if self.shutdown_event.is_set():
                    break

    # --- Public API ---------------------------------------------------------
    def scan_directory(self, directory: str,
                       use_multithreading: bool = True) -> Dict[str, FileMetadata]:
        start_time = time.time()
        directory_path = Path(directory).resolve()

        if not directory_path.exists() or not directory_path.is_dir():
            msg = f'Invalid directory (not found): {directory_path}'
            self.logger.log_system('error', msg)
            print(f"ERROR: {msg}")
            return {}

        self.logger.log_system('info', f'Starting scan of: {directory_path}')

        file_queue: PriorityQueue = PriorityQueue()
        results_queue: Queue = Queue()
        files_data: Dict[str, FileMetadata] = {}

        file_count = 0
        for root, dirs, files in os.walk(directory_path):
            dirs[:] = [d for d in dirs
                       if not self.should_exclude(os.path.join(root, d))]
            for filename in files:
                if self.shutdown_event.is_set():
                    break
                filepath = os.path.join(root, filename)
                if not self.should_exclude(filepath):
                    priority, _ = self.get_file_priority(filepath)
                    file_queue.put((priority, filepath))
                    file_count += 1

        print(f"Found {file_count} files to scan...")

        if use_multithreading and file_count > 10:
            threads = []
            for _ in range(self.worker_threads):
                t = threading.Thread(
                    target=self._scan_file_worker,
                    args=(file_queue, results_queue, str(directory_path)),
                    daemon=True,
                )
                t.start()
                threads.append(t)

            file_queue.join()
            for _ in range(self.worker_threads):
                file_queue.put(self.POISON_PILL)
            for t in threads:
                t.join(timeout=5)
        else:
            while not file_queue.empty():
                priority, filepath = file_queue.get()
                if filepath and not self.should_exclude(filepath):
                    metadata = self.get_file_metadata(filepath)
                    if metadata:
                        relative_path = os.path.relpath(filepath, directory_path)
                        metadata.path = relative_path
                        results_queue.put((priority, metadata))

        while True:
            try:
                _, metadata = results_queue.get_nowait()
            except Empty:
                break
            files_data[metadata.path] = metadata

        duration = time.time() - start_time
        cpu_usage = psutil.cpu_percent() if HAS_PSUTIL else 0
        memory_usage = (psutil.Process().memory_info().rss / 1024 / 1024
                        if HAS_PSUTIL else 0)
        self.logger.log_performance(
            operation='directory_scan',
            duration=duration,
            files_scanned=len(files_data),
            directory=str(directory_path),
            cpu_percent=cpu_usage,
            memory_mb=memory_usage,
        )

        print(f"✓ Scan completed: {len(files_data)} files in {duration:.2f}s")
        return files_data
