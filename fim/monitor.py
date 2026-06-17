"""Top-level orchestrator that ties scanner + db + logger + security together."""

import os
import signal
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from .config import ConfigManager
from .database import DatabaseManager
from .log_handlers import JSONLogger
from .models import ChangeEvent
from .reporting import generate_report, print_statistics
from .scanner import FileScanner, HAS_PSUTIL
from .security import SecurityAnalyzer

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore


class EnterpriseFileIntegrityMonitor:
    """Coordinates scanning, change detection, security analysis, and persistence."""

    def __init__(self, config_file: str = "fim_config.json",
                 db_path: str = "fim_database.db"):
        self.config = ConfigManager(config_file)
        self.db = DatabaseManager(db_path)
        self.logger = JSONLogger(self.config.get('logging.log_directory', 'logs'))

        self.shutdown_event = threading.Event()
        self.scanner = FileScanner(self.config, self.logger, self.shutdown_event)
        self.security = SecurityAnalyzer(self.config, self.logger)

        self.monitoring = False
        self.stats: Dict = {
            'files_scanned': 0,
            'changes_detected': 0,
            'scan_duration': 0,
            'errors': 0,
        }

        try:
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
        except (ValueError, AttributeError):
            # Some embedded contexts (e.g. background threads) can't set signals.
            pass

        self.logger.log_system('info', 'Enterprise FIM initialized',
                               config_file=config_file, db_path=db_path)

    def _signal_handler(self, signum, frame):
        print("\n\nReceived shutdown signal. Cleaning up...")
        self.shutdown_event.set()
        self.monitoring = False

    # --- Public API ---------------------------------------------------------
    def scan_directory(self, directory: str) -> Dict:
        files_data = self.scanner.scan_directory(directory)
        self.stats['files_scanned'] = len(files_data)
        return files_data

    def create_baseline(self, directories: List[str]) -> None:
        print("\n" + "=" * 70)
        print("CREATING BASELINE")
        print("=" * 70)

        any_success = False
        for directory in directories:
            print(f"\nScanning: {directory}")
            files_data = self.scanner.scan_directory(directory)
            if not files_data:
                print(f"⚠ Skipped {directory!r}: no files indexed "
                      "(directory missing, empty, or all files excluded).")
                continue
            print(f"Saving {len(files_data)} files to baseline...")
            self.db.save_baseline_batch(files_data.values(), directory)
            self.logger.log_system('info', 'Baseline created',
                                   directory=directory,
                                   file_count=len(files_data))
            any_success = True

        if any_success:
            print(f"\n✓ Baseline created successfully")
        else:
            print(f"\n✗ Baseline creation failed: "
                  "no files were indexed for any directory.")
        print(f"Database: {self.db.db_path}")
        print("=" * 70)

    def check_integrity(self, directory: str) -> Dict:
        start_time = time.time()

        baseline = self.db.get_baseline(directory)
        if not baseline:
            self.logger.log_system('error', 'No baseline found',
                                   directory=directory)
            print(f"ERROR: No baseline found for {directory}")
            print("Create a baseline first using --create-baseline")
            return {}

        current_state = self.scanner.scan_directory(directory)
        self.stats['files_scanned'] = len(current_state)

        changes: Dict[str, List[ChangeEvent]] = {
            'modified': [], 'added': [], 'deleted': []
        }
        directory_abs = str(Path(directory).resolve())

        # --- Modifications & deletions --------------------------------------
        for filepath, old_metadata in baseline.items():
            if filepath in current_state:
                new_metadata = current_state[filepath]
                if old_metadata.hash == new_metadata.hash:
                    continue

                _, severity = self.scanner.get_file_priority(filepath)
                abs_path = os.path.join(directory_abs, filepath)
                analysis = self.security.analyze_file(abs_path,
                                                      rel_path=filepath)
                is_honey = self.security.is_honeypot(abs_path)
                severity = SecurityAnalyzer.derive_severity(
                    severity, analysis, is_honey)

                details = {
                    'old_modified': old_metadata.modified_time,
                    'new_modified': new_metadata.modified_time,
                    'size_change': new_metadata.size - old_metadata.size,
                }
                if is_honey:
                    details['honeypot'] = True
                details.update(analysis)

                event = ChangeEvent(
                    event_type='modified',
                    timestamp=datetime.now().isoformat(),
                    file_path=filepath,
                    old_hash=old_metadata.hash,
                    new_hash=new_metadata.hash,
                    old_size=old_metadata.size,
                    new_size=new_metadata.size,
                    severity=severity,
                    details=details,
                )
                changes['modified'].append(event)
            else:
                _, severity = self.scanner.get_file_priority(filepath)
                abs_path = os.path.join(directory_abs, filepath)
                is_honey = self.security.is_honeypot(abs_path)
                if is_honey:
                    severity = 'critical'

                details = {'deleted_time': datetime.now().isoformat()}
                if is_honey:
                    details['honeypot'] = True
                    details['honeypot_alert'] = 'Honeypot file was deleted'

                event = ChangeEvent(
                    event_type='deleted',
                    timestamp=datetime.now().isoformat(),
                    file_path=filepath,
                    old_hash=old_metadata.hash,
                    old_size=old_metadata.size,
                    severity=severity,
                    details=details,
                )
                changes['deleted'].append(event)

        # --- Additions ------------------------------------------------------
        for filepath, new_metadata in current_state.items():
            if filepath in baseline:
                continue

            _, severity = self.scanner.get_file_priority(filepath)
            abs_path = os.path.join(directory_abs, filepath)
            analysis = self.security.analyze_file(abs_path, rel_path=filepath)
            is_honey = self.security.is_honeypot(abs_path)
            severity = SecurityAnalyzer.derive_severity(
                severity, analysis, is_honey)

            details = {
                'created_time': new_metadata.created_time,
                'permissions': new_metadata.permissions,
                'owner': new_metadata.owner,
            }
            if is_honey:
                details['honeypot'] = True
            details.update(analysis)

            event = ChangeEvent(
                event_type='added',
                timestamp=datetime.now().isoformat(),
                file_path=filepath,
                new_hash=new_metadata.hash,
                new_size=new_metadata.size,
                severity=severity,
                details=details,
            )
            changes['added'].append(event)

        # --- Batch ransomware heuristic across all events -------------------
        all_events = changes['modified'] + changes['added'] + changes['deleted']
        ransomware = self.security.detect_ransomware(all_events)
        if ransomware:
            for ev in changes['modified'] + changes['added']:
                ev.severity = 'critical'
                if ev.details is None:
                    ev.details = {}
                ev.details['ransomware_indicator'] = True
            self.logger.log_alert({
                'alert_type': 'ransomware_suspected',
                'directory': directory,
                'severity': 'critical',
                **ransomware,
            })
            print(f"\nRANSOMWARE INDICATORS DETECTED (score={ransomware['score']})")
            for r in ransomware['reasons']:
                print(f"   - {r}")

        # --- Persist (batched) ---------------------------------------------
        self.db.save_changes_batch(all_events)
        for ev in all_events:
            self.logger.log_event(ev)
        for ev in changes['deleted']:
            self.db.delete_baseline_entry(ev.file_path)
        if changes['added']:
            self.db.save_baseline_batch(
                [current_state[ev.file_path] for ev in changes['added']],
                directory,
            )

        duration = time.time() - start_time
        self.stats['scan_duration'] = duration
        total_changes = sum(len(v) for v in changes.values())
        self.stats['changes_detected'] = total_changes

        cpu_usage = psutil.cpu_percent() if HAS_PSUTIL and psutil else 0
        memory_usage = (psutil.Process().memory_info().rss / 1024 / 1024
                        if HAS_PSUTIL and psutil else 0)
        self.db.save_scan_stats(
            directory=directory,
            files_scanned=len(current_state),
            changes_detected=total_changes,
            duration=duration,
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
        )
        return changes

    def generate_report(self, changes: Dict) -> bool:
        return generate_report(changes, self.stats)

    def monitor_continuous(self, directories: List[str],
                           interval: int = 60) -> None:
        self.monitoring = True
        interval = max(10, min(interval, 3600))

        print("\n" + "=" * 70)
        print("CONTINUOUS MONITORING STARTED")
        print("=" * 70)
        print(f"Directories: {', '.join(directories)}")
        print(f"Scan Interval: {interval} seconds")
        print(f"Worker Threads: {self.scanner.worker_threads}")
        print("Press Ctrl+C to stop")
        print("=" * 70)

        self.logger.log_system('info', 'Monitoring started',
                               directories=directories, interval=interval)

        scan_count = 0
        try:
            while self.monitoring and not self.shutdown_event.is_set():
                scan_count += 1
                print(f"\n[Scan #{scan_count}] "
                      f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

                for directory in directories:
                    print(f"\nChecking: {directory}")
                    self.stats = {
                        'files_scanned': 0,
                        'changes_detected': 0,
                        'scan_duration': 0,
                        'errors': 0,
                    }
                    changes = self.check_integrity(directory)
                    if changes:
                        has_changes = self.generate_report(changes)
                        if has_changes:
                            total = sum(len(v) for v in changes.values())
                            threshold = self.config.get(
                                'alerting.alert_threshold', 10)
                            if total >= threshold:
                                self.logger.log_alert({
                                    'message': f'Alert threshold exceeded: '
                                               f'{total} changes',
                                    'directory': directory,
                                    'threshold': threshold,
                                    'severity': 'high',
                                })
                    else:
                        print("✓ No changes detected")

                print(f"\nNext scan in {interval} seconds...")
                for _ in range(interval):
                    if self.shutdown_event.is_set():
                        break
                    time.sleep(1)
        except KeyboardInterrupt:
            print("\n\nMonitoring stopped by user")
        finally:
            self.monitoring = False
            self.logger.log_system('info', 'Monitoring stopped',
                                   total_scans=scan_count)
            print("\n" + "=" * 70)
            print("MONITORING STOPPED")
            print("=" * 70)

    def show_statistics(self, hours: int = 24) -> None:
        history = self.db.get_change_history(hours=hours)
        print_statistics(history, hours)

    def cleanup(self) -> None:
        self.db.close()
        print("Resources cleaned up")
