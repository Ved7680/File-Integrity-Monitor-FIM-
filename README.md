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

## 🆚 How FIM Compares to Other Tools

FIM is positioned as a **single-machine, local-first integrity + threat-detection toolkit** with a native dark desktop GUI. Most FIM products are either CLI-only daemons (AIDE, Tripwire OSS, Samhain) or full HIDS platforms that bundle FIM into a server-agent architecture (OSSEC/Wazuh, Auditbeat, CrowdStrike Falcon). This project sits in between - more than a hash differ, less than an enterprise platform.

### Feature matrix

| Capability | **This FIM** | AIDE | Tripwire OSS | OSSEC / Wazuh | Auditbeat | Samhain | Commercial (Tripwire Ent., Qualys FIM, Falcon) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Native desktop GUI | ✅ dark | ❌ | ❌ | ⚠️ web | ⚠️ Kibana | ❌ | ⚠️ web console |
| SHA-256 baseline + diff | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Indexed/queryable baseline DB | ✅ SQLite | ⚠️ text/binary file | ⚠️ signed binary | ✅ SQLite | ✅ Elasticsearch | ⚠️ signed flat file | ✅ |
| Multi-threaded scanning | ✅ | ⚠️ | ⚠️ | ✅ | ✅ | ⚠️ | ✅ |
| Built-in continuous scheduler | ✅ | ⚠️ external cron | ⚠️ external cron | ✅ | ✅ | ✅ | ✅ |
| Real-time FS events (inotify / USN) | ❌ | ❌ | ❌ | ✅ | ✅ | ⚠️ | ✅ |
| Structured JSON logs by default | ✅ | ❌ text | ❌ text | ✅ | ✅ | ⚠️ | ✅ |
| Hash caching with TTL | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **Shannon entropy analysis** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ some |
| **YARA rule scanning** | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ✅ |
| **Ransomware heuristic + extension list** | ✅ | ❌ | ❌ | ⚠️ via rules | ❌ | ❌ | ✅ |
| **Honeypot file tracking** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ separate product |
| **Authenticode signature verification** | ✅ | ❌ | ❌ | ⚠️ via SCA | ❌ | ❌ | ✅ |
| **Process attribution** | ⚠️ psutil polling | ❌ | ❌ | ✅ whodata | ✅ auditd | ❌ | ✅ kernel hooks |
| **Tamper-evident baseline DB** | ❌ | ⚠️ external sig | ✅ signed | ⚠️ via ACLs | ⚠️ | ✅ signed + encrypted | ⚠️ |
| Multi-host centralized console | ❌ | ❌ | ❌ | ✅ | ✅ Elastic | ⚠️ Beltane | ✅ |
| SIEM integration | ⚠️ JSON files | ⚠️ report parsing | ⚠️ | ✅ | ✅ native | ⚠️ | ✅ |
| Agent–server model | ❌ standalone | ❌ standalone | ❌ standalone | ✅ | ✅ | ⚠️ optional | ✅ |
| Cost | Free / OSS | Free / OSS | Free / OSS | Free / OSS | Free / OSS | Free / OSS | $$ per host |
| Setup complexity | Low (one command) | Medium | Medium | High | Medium–High | High | Vendor-managed |

> Notes on the table: `✅` = first-class built-in, `⚠️` = available but conditional / partial / requires extra setup, `❌` = not supported. FIM's process attribution is marked `⚠️` because it polls open file handles via `psutil` — short-lived writers are not reliably captured. Wazuh's `whodata` and Auditbeat's `auditd` integration use kernel audit subsystems and capture writers at write time, which is strictly more accurate.

### Where FIM stands out

- **One machine, one process.** No agent, no server, no Elastic cluster, no subscription. `python fim_gui.py` and you're monitoring.
- **Desktop GUI for FIM.** Most integrity tools are pure CLI — this ships a native dark workspace with a live monitor, log tail, severity charts, and one-click honeypot deployment.
- **Threat detection bundled with the scanner.** Entropy analysis, ransomware-extension scoring, honeypots, YARA, Authenticode verification, and (best-effort) process attribution all live in the same engine — no plugin ecosystem, no glue scripts.
- **Honeypots as a first-class primitive.** Drop decoy files in sensitive locations; any change raises a critical alert. Almost no FIM tool treats this as a core feature.
- **JSON-by-default logging.** Four rotation-managed streams (events / alerts / system / performance), ready for `jq`, Splunk, or any log shipper without translation.
- **Lightweight footprint.** Two required dependencies (`customtkinter`, `Pillow`). `psutil`, `yara-python`, and `pywin32` are optional and degrade gracefully.

### Scope & tradeoffs

FIM is deliberately scoped as a single-host, GUI-first, locally administered tool. The following are intentional tradeoffs - each comes with practical guidance for users whose needs go further.

- **Polled scanning, not kernel-level real-time.** FIM rescans on a configurable interval (default 60 s) instead of hooking into inotify (Linux) or the USN journal (Windows). This keeps the codebase portable, kernel-module-free, and runnable without elevated privileges. For sub-second detection, layer on **Wazuh** or **Auditbeat**, both of which forward kernel events.
- **Single-host architecture, not a centralized console.** Each install is independent. This is the right shape for personal workstations, home labs, and small fleets administered by the operator at the keyboard. Teams managing tens to hundreds of hosts should look at **Wazuh** (free) or **Tripwire Enterprise / Qualys FIM** (commercial) for rollups, RBAC, and policy distribution.
- **Best-effort process attribution.** FIM identifies the process holding an open handle on the changed file via `psutil`. Short-lived writers that have already exited won't be captured. Tools using kernel audit subsystems (`whodata` in Wazuh, `auditd` rules in Auditbeat) catch the actual writer at write time. For mission-critical attribution, run FIM alongside `auditd` and correlate.
- **Shipper-friendly JSON logs, not a native SIEM connector.** FIM writes rotated JSON-lines files to `logs/`. Any shipper that tails JSON-lines (Filebeat, Promtail, Fluent Bit, Vector, Splunk Universal Forwarder) can ingest them. There is no built-in TCP / syslog / HEC output. If your environment expects an agent that ships natively to Elastic or Splunk, **Auditbeat** or a Splunk-native FIM is a better fit.
- **Operator-grade UI, not a SOC console.** The GUI is single-user with no roles, no acknowledgement workflow, and no record of operator actions. It's designed for the person sitting at the machine, not a 24/7 monitoring team. Pair with a ticketing system if acknowledgement tracking is required.
- **Local baseline DB is not tamper-evident.** `fim_database.db` is a plain SQLite file. An attacker who can write to it can rewrite history. Mitigate by storing the DB on read-only media, an SMB share with one-way replication, or running FIM under a service account whose write permissions the attacker doesn't reach. Tools with cryptographically signed databases (**Samhain**, signed Tripwire) raise the bar for FIM-itself tampering; adding signed/encrypted baselines is on the roadmap.

### Project maturity

FIM is a young project. **AIDE**, **Tripwire**, **Samhain**, and **OSSEC** each represent 15–25 years of production deployment, peer review, and adversarial scrutiny. Use FIM today for home labs, personal workstations, small-fleet monitoring, and as a baseline for further development. For regulated workloads (PCI-DSS, HIPAA, government use) where audit defensibility is itself a requirement, lean on the established tools — at least until this project has accrued its own track record.

### Who this is for

- Home labs and personal workstations wanting more than `aide --check` in a cron job
- Developers, sysadmins, and security students who want a tactile UI to see hashes, entropy, and honeypot trips in real time
- Small teams running a handful of servers where standing up Wazuh or Elastic is overkill
- Anyone who wants honeypots, ransomware heuristics, and integrity monitoring in **one process** without buying an enterprise suite

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
