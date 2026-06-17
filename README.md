# Enterprise File Integrity Monitor (FIM)

A production-grade File Integrity Monitor designed to monitor entire systems with high performance, comprehensive logging, and enterprise features.

## 🚀 Key Features

### Performance & Scalability
- **Multi-threaded scanning** - Parallel file processing for maximum performance
- **Intelligent caching** - Reduces redundant hash calculations
- **Priority-based processing** - Critical files scanned first
- **Optimized for large filesystems** - Can monitor entire PCs without performance impact
- **Incremental scanning** - Only checks modified files
- **Configurable resource limits** - Control CPU/memory usage

### Enterprise-Grade Logging
- **100% JSON structured logs** - All events in machine-readable JSON format
- **Multiple log streams**:
  - `events.json` - File change events (modified, added, deleted)
  - `system.json` - System operations and status
  - `alerts.json` - High-severity security alerts
  - `performance.json` - Performance metrics and statistics
- **Log rotation** - Automatic log file rotation (10MB per file, 10 backups)
- **Retention management** - Configurable log retention policies

### Advanced Monitoring
- **SQLite database backend** - Efficient baseline and history storage
- **Multi-directory support** - Monitor multiple locations simultaneously
- **Pattern-based exclusions** - Flexible file/folder filtering
- **Severity classification** - Critical/High/Medium/Low priority levels
- **Real-time continuous monitoring** - Scheduled integrity checks
- **Change history tracking** - Complete audit trail

### Security Features
- **SHA-256 hashing** - Cryptographic file integrity verification
- **File metadata tracking** - Permissions, ownership, timestamps
- **Alert thresholds** - Automatic alerts for bulk changes
- **Critical file monitoring** - Special handling for executables, configs
- **Tamper detection** - Detects unauthorized modifications

## 📋 Requirements

### System Requirements
- Python 3.7 or higher
- Windows, Linux, or macOS
- Minimum 100MB disk space for database and logs
- Recommended: 4GB RAM for monitoring large directories

### Python Dependencies
```bash
pip install -r requirements.txt
```

**Required:**
- Standard library only (pathlib, sqlite3, json, hashlib, threading)

**Recommended:**
- `psutil` - For performance monitoring (CPU, memory usage)

**Optional:**
- `pywin32` - For Windows file ownership (Windows only)

## 🔧 Installation

1. **Clone or download the files:**
```bash
# Download enterprise_fim.py and requirements.txt
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Run initial setup:**
```bash
python enterprise_fim.py
```

This creates:
- `fim_config.json` - Configuration file
- `fim_database.db` - SQLite database
- `logs/` directory - JSON log files

## 🎯 Quick Start

### 1. Create Baseline (First Time)
```bash
# Single directory
python enterprise_fim.py --create-baseline /path/to/directory

# Multiple directories
python enterprise_fim.py --create-baseline /home/user/documents /etc /var/www

# Windows example
python enterprise_fim.py --create-baseline "C:\Program Files" "C:\Windows\System32"
```

### 2. Check Integrity (One-time scan)
```bash
python enterprise_fim.py --check /path/to/directory
```

### 3. Continuous Monitoring
```bash
# Monitor with default 60-second interval
python enterprise_fim.py --monitor /path/to/directory

# Monitor multiple directories with custom interval
python enterprise_fim.py --monitor /home /var/log /etc --interval 300

# Monitor every 2 minutes (120 seconds)
python enterprise_fim.py --monitor "C:\Windows" --interval 120
```

### 4. View Statistics
```bash
# Last 24 hours (default)
python enterprise_fim.py --stats

# Last 48 hours
python enterprise_fim.py --stats --hours 48
```

## ⚙️ Configuration

The system uses `fim_config.json` for all settings. Auto-created with defaults on first run.

### Key Configuration Options

```json
{
  "monitoring": {
    "scan_interval": 60,           // Default scan interval (seconds)
    "worker_threads": 4,            // Parallel scanning threads
    "max_file_size_mb": 500,        // Skip files larger than this
    "enable_incremental_scan": true // Only scan changed files
  },
  
  "exclude_patterns": [
    "*.tmp", "*.log", "*.swp",      // Temporary files
    ".git/*", "node_modules/*",     // Development directories
    "__pycache__/*", "*.pyc"        // Python cache
  ],
  
  "priority_patterns": {
    "critical": ["*.exe", "*.dll", "*.sys", "*.bat", "*.ps1"],
    "high": ["*.conf", "*.config", "*.ini", "*.xml"],
    "medium": ["*.py", "*.js", "*.java", "*.cpp"]
  },
  
  "alerting": {
    "alert_threshold": 10,          // Alert if more than N changes
    "critical_file_patterns": [     // Files to always alert on
      "*.exe", "/etc/passwd", "/etc/shadow"
    ]
  },
  
  "performance": {
    "enable_caching": true,         // Cache file hashes
    "cache_ttl_seconds": 300,       // Cache validity period
    "batch_size": 100               // Files per batch
  },
  
  "logging": {
    "log_directory": "logs",
    "retention_days": 30,
    "max_log_size_mb": 100
  }
}
```

### Modify Configuration
```bash
# Set scan interval to 2 minutes
python enterprise_fim.py --config monitoring.scan_interval=120

# Set worker threads to 8
python enterprise_fim.py --config monitoring.worker_threads=8

# Change max file size to 1GB
python enterprise_fim.py --config monitoring.max_file_size_mb=1024
```

## 📊 Log Format

All logs are in JSON format for easy parsing and analysis.

### Event Log (`logs/events.json`)
```json
{
  "timestamp": "2026-02-11T10:30:45.123456",
  "event_type": "modified",
  "file_path": "important_file.txt",
  "severity": "high",
  "old_hash": "abc123...",
  "new_hash": "def456...",
  "old_size": 1024,
  "new_size": 2048,
  "details": {
    "old_modified": 1707648645.0,
    "new_modified": 1707648745.0,
    "size_change": 1024
  }
}
```

### System Log (`logs/system.json`)
```json
{
  "timestamp": "2026-02-11T10:30:00.000000",
  "level": "info",
  "message": "Baseline created",
  "directory": "/home/user/documents",
  "file_count": 1500
}
```

### Alert Log (`logs/alerts.json`)
```json
{
  "alert_timestamp": "2026-02-11T10:35:00.000000",
  "timestamp": "2026-02-11T10:34:55.000000",
  "event_type": "modified",
  "file_path": "system.exe",
  "severity": "critical",
  "new_hash": "xyz789...",
  "details": {}
}
```

### Performance Log (`logs/performance.json`)
```json
{
  "timestamp": "2026-02-11T10:30:00.000000",
  "operation": "directory_scan",
  "duration_seconds": 15.5,
  "files_scanned": 5000,
  "directory": "/var/www",
  "cpu_percent": 35.2,
  "memory_mb": 250.5
}
```

## 🎛️ Advanced Usage

### Monitoring Production Systems

**Monitor critical system directories (Linux):**
```bash
python enterprise_fim.py --create-baseline /etc /var/www /usr/local/bin /home
python enterprise_fim.py --monitor /etc /var/www /usr/local/bin /home --interval 300
```

**Monitor Windows system directories:**
```bash
python enterprise_fim.py --create-baseline "C:\Windows\System32" "C:\Program Files"
python enterprise_fim.py --monitor "C:\Windows\System32" "C:\Program Files" --interval 300
```

### Custom Database and Config Locations
```bash
# Use custom database
python enterprise_fim.py --db /secure/location/fim.db --create-baseline /home

# Use custom config file
python enterprise_fim.py --config-file /etc/fim/config.json --monitor /var
```

### Running as Background Service

**Linux (systemd):**

Create `/etc/systemd/system/fim.service`:
```ini
[Unit]
Description=File Integrity Monitor
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/fim
ExecStart=/usr/bin/python3 /opt/fim/enterprise_fim.py --monitor /etc /var/www --interval 300
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable fim
sudo systemctl start fim
sudo systemctl status fim
```

**Windows (Task Scheduler):**
```powershell
# Create scheduled task
schtasks /create /tn "FIM Monitor" /tr "python C:\FIM\enterprise_fim.py --monitor C:\Windows --interval 300" /sc onstart /ru SYSTEM
```

### Log Analysis Examples

**Parse JSON logs with jq:**
```bash
# Count events by type
cat logs/events.json | jq -s 'group_by(.event_type) | map({type: .[0].event_type, count: length})'

# Find all critical severity events
cat logs/events.json | jq 'select(.severity == "critical")'

# Get events for specific file
cat logs/events.json | jq 'select(.file_path | contains("important.conf"))'

# Performance summary
cat logs/performance.json | jq -s 'map(.duration_seconds) | add / length'
```

**Python analysis:**
```python
import json

# Load and analyze events
events = []
with open('logs/events.json') as f:
    for line in f:
        events.append(json.loads(line))

# Group by severity
from collections import Counter
severity_counts = Counter(e['severity'] for e in events)
print(severity_counts)
```

## 🔒 Security Best Practices

1. **Secure the database:**
   ```bash
   chmod 600 fim_database.db
   ```

2. **Protect log files:**
   ```bash
   chmod 750 logs/
   chmod 640 logs/*.json
   ```

3. **Run with appropriate permissions:**
   - Use dedicated service account
   - Grant minimal required permissions
   - Never run as root unless necessary

4. **Regular baseline updates:**
   - Recreate baselines after authorized changes
   - Keep baseline backups
   - Version control your configuration

5. **Monitor the monitor:**
   - Set up alerts for FIM failures
   - Monitor log file sizes
   - Check database integrity

## 📈 Performance Tuning

### For Large Filesystems (>100K files)

1. **Increase worker threads:**
   ```bash
   python enterprise_fim.py --config monitoring.worker_threads=8
   ```

2. **Enable caching:**
   ```json
   "performance": {
     "enable_caching": true,
     "cache_ttl_seconds": 600
   }
   ```

3. **Exclude unnecessary files:**
   ```json
   "exclude_patterns": [
     "*.log", "*.tmp", "*.cache",
     ".git/*", "node_modules/*",
     "*/.npm/*", "*/.cache/*"
   ]
   ```

4. **Increase scan interval:**
   ```bash
   python enterprise_fim.py --monitor /path --interval 600
   ```

### Memory Optimization

- Increase `max_file_size_mb` limit to skip huge files
- Reduce `worker_threads` if memory constrained
- Use exclude patterns aggressively

### CPU Optimization

- Adjust worker threads based on CPU cores
- Increase scan interval during business hours
- Use priority patterns to scan critical files first

## 🐛 Troubleshooting

### Common Issues

**Permission denied errors:**
- Run with sufficient privileges
- Add problematic paths to exclude_patterns
- Check file/directory ownership

**High CPU usage:**
- Reduce worker_threads
- Increase scan_interval
- Exclude large directories

**Database locked errors:**
- Only run one FIM instance per database
- Check for zombie processes
- Verify database file permissions

**Missing changes:**
- Check exclude_patterns
- Verify baseline was created
- Check max_file_size_mb limit

### Debug Mode

Add verbose logging:
```python
# In enterprise_fim.py, add at top:
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 📝 Example Workflows

### Daily Security Scan
```bash
#!/bin/bash
# Daily security scan script

python3 enterprise_fim.py --check /etc
python3 enterprise_fim.py --check /var/www
python3 enterprise_fim.py --check /usr/local/bin

# Email results if changes detected
if [ $? -ne 0 ]; then
    cat logs/events.json | mail -s "FIM Alert" admin@example.com
fi
```

### Compliance Reporting
```python
#!/usr/bin/env python3
# Generate compliance report

import json
import sqlite3
from datetime import datetime, timedelta

db = sqlite3.connect('fim_database.db')
cursor = db.cursor()

# Get changes in last 30 days
cutoff = (datetime.now() - timedelta(days=30)).isoformat()
cursor.execute('''
    SELECT * FROM change_history 
    WHERE timestamp > ? 
    ORDER BY timestamp DESC
''', (cutoff,))

changes = cursor.fetchall()
print(f"Compliance Report - {len(changes)} changes in last 30 days")
# Generate report...
```

## 📚 API Reference

See inline documentation in `enterprise_fim.py` for detailed API reference.

Key classes:
- `EnterpriseFileIntegrityMonitor` - Main FIM engine
- `JSONLogger` - Structured logging
- `DatabaseManager` - SQLite operations
- `ConfigManager` - Configuration management

## 🤝 Contributing

This is an enterprise-grade tool. Suggested improvements:
- Email/webhook alerting integration
- Real-time file system event monitoring (watchdog)
- Distributed monitoring across multiple servers
- Dashboard UI for visualization
- Machine learning for anomaly detection

## 📄 License

This tool is provided as-is for enterprise use. Modify as needed for your environment.

## ⚠️ Disclaimer

This tool monitors file integrity but does not prevent unauthorized changes. Use as part of a comprehensive security strategy including:
- File system permissions
- Access control lists
- Audit logging
- Intrusion detection
- Regular security assessments

## 📞 Support

For issues or questions:
1. Check logs in `logs/system.json`
2. Review configuration in `fim_config.json`
3. Verify database integrity
4. Check this README for troubleshooting

---

**Version:** 1.0  
**Last Updated:** February 2026
