import os
import hashlib
import json
import time
import sys
import logging
from datetime import datetime
from pathlib import Path
import argparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('fim.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class FileIntegrityMonitor:
    def __init__(self, baseline_file='baseline.json', ignore_files=None):
        self.baseline_file = self._validate_baseline_path(baseline_file)
        self.baseline = {}
        self.monitoring = False
        self.max_file_size = 500 * 1024 * 1024  # 500MB limit
        self.ignore_files = set(ignore_files) if ignore_files else set()
        self.ignore_files.add('fim.log')  # Always ignore log file
        logger.info(f"Ignoring files: {', '.join(self.ignore_files)}")
        
    def _validate_baseline_path(self, baseline_file):
        """Validate and sanitize baseline file path"""
        try:
            # Prevent path traversal attacks
            baseline_path = Path(baseline_file).resolve()
            
            # Ensure it's a JSON file
            if baseline_path.suffix.lower() != '.json':
                baseline_path = baseline_path.with_suffix('.json')
            
            # Check if parent directory exists, create if it doesn't
            baseline_path.parent.mkdir(parents=True, exist_ok=True)
            
            return str(baseline_path)
        except Exception as e:
            logger.error(f"Invalid baseline path: {e}")
            raise ValueError(f"Invalid baseline file path: {baseline_file}")
    
    def _validate_directory(self, directory):
        """Validate that directory exists and is accessible"""
        try:
            dir_path = Path(directory).resolve()
            
            if not dir_path.exists():
                raise ValueError(f"Directory does not exist: {directory}")
            
            if not dir_path.is_dir():
                raise ValueError(f"Path is not a directory: {directory}")
            
            # Test read access
            try:
                os.listdir(dir_path)
            except PermissionError:
                raise PermissionError(f"No read permission for directory: {directory}")
            
            return dir_path
        except Exception as e:
            logger.error(f"Directory validation failed: {e}")
            raise
    
    def calculate_hash(self, filepath):
        """Calculate SHA-256 hash of a file with security checks"""
        sha256_hash = hashlib.sha256()
        
        try:
            file_size = os.path.getsize(filepath)
            
            # Skip files that are too large
            if file_size > self.max_file_size:
                logger.warning(f"Skipping large file (>{self.max_file_size/1024/1024}MB): {filepath}")
                return None
            
            with open(filepath, "rb") as f:
                # Read in chunks to handle large files efficiently
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            
            return sha256_hash.hexdigest()
            
        except PermissionError:
            logger.warning(f"Permission denied: {filepath}")
            return None
        except FileNotFoundError:
            logger.warning(f"File not found (may have been deleted): {filepath}")
            return None
        except IOError as e:
            logger.error(f"I/O error reading {filepath}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error calculating hash for {filepath}: {e}")
            return None
    
    def get_file_info(self, filepath):
        """Get file metadata with error handling"""
        try:
            stat_info = os.stat(filepath)
            file_hash = self.calculate_hash(filepath)
            
            if file_hash is None:
                return None
            
            return {
                'hash': file_hash,
                'size': stat_info.st_size,
                'modified': stat_info.st_mtime,
                'created': stat_info.st_ctime
            }
        except FileNotFoundError:
            logger.warning(f"File not found: {filepath}")
            return None
        except PermissionError:
            logger.warning(f"Permission denied: {filepath}")
            return None
        except OSError as e:
            logger.error(f"OS error accessing {filepath}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error getting file info for {filepath}: {e}")
            return None
    
    def scan_directory(self, directory):
        """Recursively scan directory and collect file information"""
        files_data = {}
        
        try:
            directory = self._validate_directory(directory)
        except Exception as e:
            logger.error(f"Cannot scan directory: {e}")
            return files_data
        
        if not self.monitoring:
            print(f"Scanning directory: {directory}")
        
        baseline_filename = os.path.basename(self.baseline_file)
        file_count = 0
        error_count = 0
        
        try:
            for root, dirs, files in os.walk(directory):
                # Skip hidden and system directories on Windows
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['$RECYCLE.BIN', 'System Volume Information']]
                
                for filename in files:
                    try:
                        # Skip hidden files, baseline file, and ignored files
                        if filename.startswith('.') or filename == baseline_filename or filename in self.ignore_files:
                            continue
                        
                        filepath = os.path.join(root, filename)
                        relative_path = os.path.relpath(filepath, directory)
                        
                        file_info = self.get_file_info(filepath)
                        if file_info and file_info['hash']:
                            files_data[relative_path] = file_info
                            file_count += 1
                            if not self.monitoring:
                                print(f"  Scanned: {relative_path}")
                        else:
                            error_count += 1
                            
                    except Exception as e:
                        error_count += 1
                        logger.error(f"Error processing file {filename}: {e}")
                        continue
        
        except KeyboardInterrupt:
            logger.info("Scan interrupted by user")
            raise
        except Exception as e:
            logger.error(f"Error during directory scan: {e}")
        
        if not self.monitoring and error_count > 0:
            logger.warning(f"Scan completed with {error_count} errors")
        
        return files_data
    
    def create_baseline(self, directory):
        """Create a baseline of file integrity"""
        try:
            print("\n=== Creating Baseline ===")
            self.baseline = self.scan_directory(directory)
            
            if not self.baseline:
                logger.error("No files were scanned. Baseline not created.")
                return False
            
            # Save baseline with error handling
            try:
                with open(self.baseline_file, 'w') as f:
                    json.dump(self.baseline, f, indent=2)
                
                # Verify the baseline was written correctly
                with open(self.baseline_file, 'r') as f:
                    verification = json.load(f)
                
                if len(verification) != len(self.baseline):
                    raise ValueError("Baseline verification failed")
                
                print(f"\nBaseline created with {len(self.baseline)} files")
                print(f"Baseline saved to: {self.baseline_file}")
                logger.info(f"Baseline created successfully with {len(self.baseline)} files")
                return True
                
            except IOError as e:
                logger.error(f"Failed to write baseline file: {e}")
                print(f"Error: Could not write baseline file: {e}")
                return False
            except json.JSONDecodeError as e:
                logger.error(f"Baseline verification failed: {e}")
                print(f"Error: Baseline file corrupted during write")
                return False
                
        except KeyboardInterrupt:
            print("\n\nBaseline creation interrupted by user")
            logger.info("Baseline creation interrupted")
            return False
        except Exception as e:
            logger.error(f"Unexpected error creating baseline: {e}")
            print(f"Error creating baseline: {e}")
            return False
    
    def load_baseline(self):
        """Load baseline from file with validation"""
        try:
            if not os.path.exists(self.baseline_file):
                logger.error(f"Baseline file not found: {self.baseline_file}")
                print(f"Baseline file '{self.baseline_file}' not found!")
                return False
            
            # Check file permissions
            if not os.access(self.baseline_file, os.R_OK):
                logger.error(f"No read permission for baseline file: {self.baseline_file}")
                print(f"Error: No read permission for baseline file")
                return False
            
            with open(self.baseline_file, 'r') as f:
                self.baseline = json.load(f)
            
            # Validate baseline structure
            if not isinstance(self.baseline, dict):
                raise ValueError("Invalid baseline format: expected dictionary")
            
            for filepath, info in self.baseline.items():
                if not isinstance(info, dict):
                    raise ValueError(f"Invalid entry for {filepath}")
                required_keys = {'hash', 'size', 'modified', 'created'}
                if not required_keys.issubset(info.keys()):
                    raise ValueError(f"Missing required keys for {filepath}")
            
            print(f"Baseline loaded: {len(self.baseline)} files")
            logger.info(f"Baseline loaded successfully: {len(self.baseline)} files")
            return True
            
        except json.JSONDecodeError as e:
            logger.error(f"Baseline file is corrupted: {e}")
            print(f"Error: Baseline file is corrupted or invalid JSON")
            return False
        except ValueError as e:
            logger.error(f"Invalid baseline format: {e}")
            print(f"Error: {e}")
            return False
        except Exception as e:
            logger.error(f"Error loading baseline: {e}")
            print(f"Error loading baseline: {e}")
            return False
    
    def check_changes(self, directory):
        """Check directory for changes and return detected changes"""
        try:
            current_state = self.scan_directory(directory)
            
            changes = {
                'modified': [],
                'added': [],
                'deleted': []
            }
            
            # Check for modified and deleted files
            for filepath, baseline_info in self.baseline.items():
                # Skip ignored files in baseline comparison
                filename = os.path.basename(filepath)
                if filename in self.ignore_files:
                    continue
                    
                if filepath in current_state:
                    current_info = current_state[filepath]
                    if current_info['hash'] != baseline_info['hash']:
                        changes['modified'].append({
                            'file': filepath,
                            'old_hash': baseline_info['hash'],
                            'new_hash': current_info['hash'],
                            'old_size': baseline_info['size'],
                            'new_size': current_info['size']
                        })
                else:
                    changes['deleted'].append(filepath)
            
            # Check for new files
            for filepath in current_state:
                if filepath not in self.baseline:
                    changes['added'].append({
                        'file': filepath,
                        'hash': current_state[filepath]['hash'],
                        'size': current_state[filepath]['size']
                    })
            
            return changes, current_state
            
        except Exception as e:
            logger.error(f"Error checking for changes: {e}")
            return {'modified': [], 'added': [], 'deleted': []}, {}
    
    def generate_alert(self, changes):
        """Generate an alert for detected changes"""
        total_changes = len(changes['modified']) + len(changes['added']) + len(changes['deleted'])
        
        if total_changes == 0:
            return False
        
        alert_msg = f"INTEGRITY VIOLATION - {total_changes} change(s) detected"
        logger.warning(alert_msg)
        
        print("\n" + "!"*60)
        print(f"⚠️  ALERT - INTEGRITY VIOLATION DETECTED!")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("!"*60)
        
        if changes['modified']:
            print(f"\n🔴 [MODIFIED FILES: {len(changes['modified'])}]")
            for item in changes['modified']:
                print(f"  • {item['file']}")
                print(f"    Old Hash: {item['old_hash'][:16]}...")
                print(f"    New Hash: {item['new_hash'][:16]}...")
                print(f"    Size: {item['old_size']} → {item['new_size']} bytes")
                logger.warning(f"Modified: {item['file']}")
        
        if changes['added']:
            print(f"\n🟡 [NEW FILES: {len(changes['added'])}]")
            for item in changes['added']:
                print(f"  • {item['file']}")
                print(f"    Hash: {item['hash'][:16]}...")
                print(f"    Size: {item['size']} bytes")
                logger.warning(f"Added: {item['file']}")
        
        if changes['deleted']:
            print(f"\n🔵 [DELETED FILES: {len(changes['deleted'])}]")
            for filepath in changes['deleted']:
                print(f"  • {filepath}")
                logger.warning(f"Deleted: {filepath}")
        
        print("\n" + "!"*60 + "\n")
        return True
    
    def monitor_realtime(self, directory, interval=5, update_baseline=False):
        """Monitor directory in real-time for changes"""
        try:
            if not self.load_baseline():
                print("Please create a baseline first using --create-baseline")
                return
            
            # Validate interval
            if interval < 1:
                logger.warning("Interval too small, setting to 1 second")
                interval = 1
            elif interval > 3600:
                logger.warning("Interval too large, setting to 1 hour")
                interval = 3600
            
            self.monitoring = True
            print("\n" + "="*60)
            print(f"🔍 REAL-TIME MONITORING STARTED")
            print(f"Directory: {directory}")
            print(f"Check Interval: {interval} seconds")
            print(f"Auto-update baseline: {'Yes' if update_baseline else 'No'}")
            print(f"Press Ctrl+C to stop monitoring")
            print("="*60 + "\n")
            
            logger.info(f"Real-time monitoring started for {directory}")
            
            while True:
                try:
                    print(f"Scanning... {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    
                    changes, current_state = self.check_changes(directory)
                    
                    if self.generate_alert(changes):
                        if update_baseline:
                            print("ℹ️  Auto-updating baseline with current state...")
                            self.baseline = current_state
                            try:
                                with open(self.baseline_file, 'w') as f:
                                    json.dump(self.baseline, f, indent=2)
                                print("✓ Baseline updated\n")
                                logger.info("Baseline auto-updated")
                            except Exception as e:
                                logger.error(f"Failed to update baseline: {e}")
                                print(f"⚠️  Failed to update baseline: {e}\n")
                    else:
                        print("✓ No changes detected\n")
                    
                    time.sleep(interval)
                    
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    logger.error(f"Error during monitoring cycle: {e}")
                    print(f"Error: {e}")
                    print(f"Continuing monitoring...\n")
                    time.sleep(interval)
                    
        except KeyboardInterrupt:
            print("\n" + "="*60)
            print(f"🛑 MONITORING STOPPED")
            print("="*60)
            logger.info("Monitoring stopped by user")
        except Exception as e:
            logger.error(f"Fatal error in monitoring: {e}")
            print(f"\nFatal error: {e}")
            print("Monitoring stopped")
    
    def monitor_once(self, directory):
        """Perform a single check for changes"""
        try:
            if not self.load_baseline():
                print("Please create a baseline first using --create-baseline")
                return
            
            print("\n=== Monitoring for Changes ===")
            changes, _ = self.check_changes(directory)
            
            self.report_changes(changes)
            
        except Exception as e:
            logger.error(f"Error during monitoring: {e}")
            print(f"Error: {e}")
    
    def report_changes(self, changes):
        """Generate a report of detected changes"""
        print("\n" + "="*60)
        print(f"INTEGRITY CHECK REPORT - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        total_changes = len(changes['modified']) + len(changes['added']) + len(changes['deleted'])
        
        if total_changes == 0:
            print("\n✓ No changes detected. All files match baseline.")
            logger.info("Integrity check passed - no changes")
        else:
            print(f"\n⚠ {total_changes} change(s) detected!")
            logger.warning(f"Integrity check found {total_changes} changes")
            
            if changes['modified']:
                print(f"\n[MODIFIED FILES: {len(changes['modified'])}]")
                for item in changes['modified']:
                    print(f"  • {item['file']}")
                    print(f"    Old Hash: {item['old_hash'][:16]}...")
                    print(f"    New Hash: {item['new_hash'][:16]}...")
                    print(f"    Size: {item['old_size']} → {item['new_size']} bytes")
            
            if changes['added']:
                print(f"\n[NEW FILES: {len(changes['added'])}]")
                for item in changes['added']:
                    print(f"  • {item['file']}")
                    print(f"    Hash: {item['hash'][:16]}...")
                    print(f"    Size: {item['size']} bytes")
            
            if changes['deleted']:
                print(f"\n[DELETED FILES: {len(changes['deleted'])}]")
                for filepath in changes['deleted']:
                    print(f"  • {filepath}")
        
        print("\n" + "="*60)


def main():
    parser = argparse.ArgumentParser(
        description='File Integrity Monitor for Windows',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Create baseline:       python fim.py --create-baseline C:\\MyFolder
  One-time check:        python fim.py --monitor C:\\MyFolder
  Real-time monitoring:  python fim.py --monitor C:\\MyFolder --realtime
  Custom interval:       python fim.py --monitor C:\\MyFolder --realtime --interval 10
  Auto-update baseline:  python fim.py --monitor C:\\MyFolder --realtime --update-baseline
  Ignore files:          python fim.py --monitor C:\\MyFolder --ignore temp.txt cache.db logs.txt
        """
    )
    
    parser.add_argument('--create-baseline', metavar='DIR', 
                        help='Create a baseline for the specified directory')
    parser.add_argument('--monitor', metavar='DIR',
                        help='Monitor the specified directory for changes')
    parser.add_argument('--baseline', default='baseline.json',
                        help='Baseline file name (default: baseline.json)')
    parser.add_argument('--realtime', action='store_true',
                        help='Enable real-time continuous monitoring')
    parser.add_argument('--interval', type=int, default=5,
                        help='Scan interval in seconds for real-time monitoring (default: 5)')
    parser.add_argument('--update-baseline', action='store_true',
                        help='Automatically update baseline after detecting changes (use with caution)')
    parser.add_argument('--ignore', nargs='+', metavar='FILE',
                        help='File(s) to ignore during monitoring (e.g., --ignore temp.txt cache.db)')
    
    args = parser.parse_args()
    
    try:
        fim = FileIntegrityMonitor(baseline_file=args.baseline, ignore_files=args.ignore)
        
        if args.create_baseline:
            fim.create_baseline(args.create_baseline)
        elif args.monitor:
            if args.realtime:
                fim.monitor_realtime(args.monitor, interval=args.interval, 
                                   update_baseline=args.update_baseline)
            else:
                fim.monitor_once(args.monitor)
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        logger.info("Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        print(f"\nFatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()