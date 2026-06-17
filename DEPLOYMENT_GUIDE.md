# Enterprise FIM - Deployment Guide

## Table of Contents
1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Installation Steps](#installation-steps)
3. [Initial Configuration](#initial-configuration)
4. [Production Deployment](#production-deployment)
5. [Monitoring Setup](#monitoring-setup)
6. [Maintenance Procedures](#maintenance-procedures)

---

## Pre-Deployment Checklist

### System Requirements
- [ ] Python 3.7+ installed
- [ ] Minimum 100MB free disk space
- [ ] Appropriate permissions for target directories
- [ ] Network access (if using remote logging/alerting)

### Planning
- [ ] Identify critical directories to monitor
- [ ] Determine scan frequency requirements
- [ ] Plan log storage location and retention
- [ ] Identify exclusion patterns
- [ ] Set alert thresholds
- [ ] Plan baseline update schedule

---

## Installation Steps

### 1. Basic Installation

```bash
# Create installation directory
sudo mkdir -p /opt/fim
cd /opt/fim

# Copy files
sudo cp enterprise_fim.py /opt/fim/
sudo cp requirements.txt /opt/fim/
sudo cp fim_config_example.json /opt/fim/fim_config.json

# Install dependencies
sudo pip3 install -r requirements.txt

# Set permissions
sudo chmod 750 /opt/fim
sudo chmod 640 /opt/fim/*.py
sudo chmod 640 /opt/fim/*.json

# Create log directory
sudo mkdir -p /opt/fim/logs
sudo chmod 750 /opt/fim/logs
```

### 2. Windows Installation

```powershell
# Create installation directory
New-Item -Path "C:\FIM" -ItemType Directory

# Copy files
Copy-Item enterprise_fim.py "C:\FIM\"
Copy-Item requirements.txt "C:\FIM\"
Copy-Item fim_config_example.json "C:\FIM\fim_config.json"

# Install dependencies
pip install -r requirements.txt

# Create log directory
New-Item -Path "C:\FIM\logs" -ItemType Directory
```

---

## Initial Configuration

### 1. Customize Configuration

Edit `fim_config.json` based on your environment:

**For Small Environments (<10K files):**
```json
{
  "monitoring": {
    "scan_interval": 60,
    "worker_threads": 2,
    "max_file_size_mb": 500
  }
}
```

**For Medium Environments (10K-100K files):**
```json
{
  "monitoring": {
    "scan_interval": 120,
    "worker_threads": 4,
    "max_file_size_mb": 500
  }
}
```

**For Large Environments (>100K files):**
```json
{
  "monitoring": {
    "scan_interval": 300,
    "worker_threads": 8,
    "max_file_size_mb": 1024
  }
}
```

### 2. Define Watch Directories

**Linux/Unix Systems:**
```json
{
  "watch_directories": [
    "/etc",
    "/var/www",
    "/usr/local/bin",
    "/home",
    "/opt"
  ]
}
```

**Windows Systems:**
```json
{
  "watch_directories": [
    "C:\\Windows\\System32",
    "C:\\Program Files",
    "C:\\Users",
    "C:\\inetpub\\wwwroot"
  ]
}
```

### 3. Configure Exclusions

Add environment-specific exclusions:

**For Development Servers:**
```json
{
  "exclude_patterns": [
    "*/node_modules/*",
    "*/.git/*",
    "*/__pycache__/*",
    "*/venv/*",
    "*/env/*",
    "*.pyc",
    "*.log"
  ]
}
```

**For Web Servers:**
```json
{
  "exclude_patterns": [
    "*/cache/*",
    "*/tmp/*",
    "*/temp/*",
    "*.log",
    "*.access",
    "*/sessions/*"
  ]
}
```

---

## Production Deployment

### Linux Deployment

#### Option 1: systemd Service

Create `/etc/systemd/system/fim.service`:

```ini
[Unit]
Description=Enterprise File Integrity Monitor
After=network.target
Documentation=file:///opt/fim/README.md

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/fim
ExecStart=/usr/bin/python3 /opt/fim/enterprise_fim.py --monitor /etc /var/www /usr/local/bin --interval 300
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/fim/logs /opt/fim/fim_database.db

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable fim
sudo systemctl start fim
sudo systemctl status fim

# View logs
sudo journalctl -u fim -f
```

#### Option 2: Cron Job (One-time scans)

Add to crontab:
```bash
# Edit crontab
sudo crontab -e

# Add entry - Run every hour
0 * * * * /usr/bin/python3 /opt/fim/enterprise_fim.py --check /etc >> /var/log/fim-cron.log 2>&1

# Or every 6 hours
0 */6 * * * /usr/bin/python3 /opt/fim/enterprise_fim.py --check /var/www >> /var/log/fim-cron.log 2>&1
```

### Windows Deployment

#### Option 1: Windows Service (with NSSM)

```powershell
# Download and install NSSM
# https://nssm.cc/download

# Install service
nssm install FIM "C:\Python39\python.exe" "C:\FIM\enterprise_fim.py --monitor C:\Windows\System32 C:\Program Files --interval 300"

# Set working directory
nssm set FIM AppDirectory "C:\FIM"

# Set service to auto-start
nssm set FIM Start SERVICE_AUTO_START

# Start service
nssm start FIM

# Check status
nssm status FIM
```

#### Option 2: Task Scheduler

```powershell
# Create scheduled task
$action = New-ScheduledTaskAction -Execute 'python.exe' -Argument 'C:\FIM\enterprise_fim.py --monitor "C:\Windows\System32" --interval 300' -WorkingDirectory 'C:\FIM'

$trigger = New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 3

Register-ScheduledTask -TaskName "FIM Monitor" -Action $action -Trigger $trigger -Principal $principal -Settings $settings

# Start task
Start-ScheduledTask -TaskName "FIM Monitor"
```

---

## Monitoring Setup

### 1. Create Initial Baseline

**Critical Files Only (Fast):**
```bash
# Linux
python3 enterprise_fim.py --create-baseline /etc /usr/local/bin

# Windows
python enterprise_fim.py --create-baseline "C:\Windows\System32"
```

**Complete System (Slow):**
```bash
# Linux - May take hours
python3 enterprise_fim.py --create-baseline / --config monitoring.worker_threads=8

# Windows
python enterprise_fim.py --create-baseline "C:\" --config monitoring.worker_threads=8
```

### 2. Test Monitoring

```bash
# Single check
python3 enterprise_fim.py --check /etc

# Short monitoring test (5 minutes)
timeout 300 python3 enterprise_fim.py --monitor /etc --interval 30
```

### 3. Enable Continuous Monitoring

Start the service (see Production Deployment above)

### 4. Verify Operations

**Check logs:**
```bash
# Linux
tail -f /opt/fim/logs/system.json | jq .
tail -f /opt/fim/logs/events.json | jq .

# Windows
Get-Content "C:\FIM\logs\system.json" -Wait | ConvertFrom-Json
```

**Check database:**
```bash
sqlite3 fim_database.db "SELECT COUNT(*) FROM baseline;"
sqlite3 fim_database.db "SELECT COUNT(*) FROM change_history;"
```

**Check stats:**
```bash
python3 enterprise_fim.py --stats --hours 24
```

---

## Maintenance Procedures

### Daily Tasks

1. **Review alerts:**
```bash
# Check for critical events
cat logs/alerts.json | jq 'select(.severity == "critical")'
```

2. **Verify service is running:**
```bash
# Linux
systemctl status fim

# Windows
sc query FIM
```

### Weekly Tasks

1. **Review change history:**
```bash
python3 enterprise_fim.py --stats --hours 168
```

2. **Check disk usage:**
```bash
du -sh logs/
du -sh fim_database.db
```

3. **Rotate logs if needed:**
```bash
# Logs auto-rotate at 10MB, but you can manually archive
tar -czf logs_archive_$(date +%Y%m%d).tar.gz logs/
```

### Monthly Tasks

1. **Update baseline after authorized changes:**
```bash
# Review changes first
python3 enterprise_fim.py --stats --hours 720

# If legitimate, recreate baseline
python3 enterprise_fim.py --create-baseline /etc /var/www
```

2. **Vacuum database:**
```bash
sqlite3 fim_database.db "VACUUM;"
```

3. **Clean old change history:**
```bash
# Keep only 90 days
sqlite3 fim_database.db "DELETE FROM change_history WHERE timestamp < datetime('now', '-90 days');"
```

4. **Backup database:**
```bash
cp fim_database.db fim_database_$(date +%Y%m%d).db.backup
```

### Performance Tuning

**If scans are too slow:**
1. Increase worker threads: `--config monitoring.worker_threads=8`
2. Reduce monitored directories
3. Add more exclusion patterns
4. Increase max_file_size_mb limit

**If using too much memory:**
1. Decrease worker threads
2. Reduce cache TTL
3. Increase scan interval

**If missing changes:**
1. Check exclusion patterns
2. Verify baseline is current
3. Check max_file_size_mb isn't excluding files

---

## Troubleshooting

### Service Won't Start

**Linux:**
```bash
# Check service status
systemctl status fim

# Check logs
journalctl -u fim -n 50

# Test manually
cd /opt/fim
python3 enterprise_fim.py --check /etc
```

**Windows:**
```powershell
# Check service status
Get-Service FIM

# Check event log
Get-EventLog -LogName Application -Source FIM -Newest 20

# Test manually
cd C:\FIM
python enterprise_fim.py --check "C:\Windows"
```

### High CPU Usage

1. Check worker threads: `jq .monitoring.worker_threads fim_config.json`
2. Increase scan interval
3. Add CPU limiting (Linux):
```bash
# Edit service file
CPUQuota=50%  # Limit to 50% CPU
```

### Database Locked Errors

1. Check for multiple instances:
```bash
ps aux | grep enterprise_fim.py
```

2. Kill old processes:
```bash
pkill -f enterprise_fim.py
```

3. Restart service

### Permission Errors

**Linux:**
```bash
# Run as root or use sudo
sudo python3 enterprise_fim.py --check /etc

# Or adjust service user in systemd
User=root
```

**Windows:**
```powershell
# Run as administrator
# Or set service to run as SYSTEM
```

---

## Best Practices

1. **Start Small:** Begin with critical directories only
2. **Test First:** Run manual checks before enabling continuous monitoring
3. **Monitor the Monitor:** Set up alerts for FIM failures
4. **Regular Baselines:** Update baselines monthly or after changes
5. **Backup Everything:** Database, logs, and config files
6. **Document Changes:** Keep a log of authorized modifications
7. **Review Alerts:** Check alerts daily, don't ignore them
8. **Tune Performance:** Adjust based on your environment
9. **Secure Files:** Protect database and logs from tampering
10. **Plan Capacity:** Monitor disk usage for logs and database

---

## Security Hardening

### File Permissions (Linux)

```bash
# FIM directory
sudo chmod 750 /opt/fim
sudo chown root:root /opt/fim

# Python script
sudo chmod 550 /opt/fim/enterprise_fim.py
sudo chown root:root /opt/fim/enterprise_fim.py

# Configuration
sudo chmod 640 /opt/fim/fim_config.json
sudo chown root:root /opt/fim/fim_config.json

# Database
sudo chmod 600 /opt/fim/fim_database.db
sudo chown root:root /opt/fim/fim_database.db

# Logs
sudo chmod 750 /opt/fim/logs
sudo chmod 640 /opt/fim/logs/*.json
sudo chown -R root:root /opt/fim/logs
```

### AppArmor Profile (Linux)

Create `/etc/apparmor.d/opt.fim.enterprise_fim`:

```
#include <tunables/global>

/opt/fim/enterprise_fim.py {
  #include <abstractions/base>
  #include <abstractions/python>

  /opt/fim/** rw,
  /etc/** r,
  /var/www/** r,
  /usr/local/bin/** r,
  
  # Allow writing to own directory
  /opt/fim/logs/** rw,
  /opt/fim/fim_database.db rw,
  
  # Deny everything else
  deny /home/** rw,
  deny /root/** rw,
}
```

Load profile:
```bash
sudo apparmor_parser -r /etc/apparmor.d/opt.fim.enterprise_fim
```

---

## Rollback Procedures

If FIM causes issues:

1. **Stop the service:**
```bash
# Linux
sudo systemctl stop fim

# Windows
Stop-Service FIM
```

2. **Restore previous baseline:**
```bash
cp fim_database_backup.db fim_database.db
```

3. **Revert configuration:**
```bash
cp fim_config.json.backup fim_config.json
```

4. **Test manually:**
```bash
python3 enterprise_fim.py --check /etc
```

5. **Restart if OK:**
```bash
sudo systemctl start fim
```

---

## Support and Resources

- **Log Files:** Check `logs/system.json` for errors
- **Database:** Use SQLite browser to inspect database
- **Performance:** Use `--stats` command regularly
- **Configuration:** Reference `fim_config_example.json`
- **Documentation:** See `README.md`

---

**Deployment Checklist:**

- [ ] System requirements met
- [ ] Files installed
- [ ] Configuration customized
- [ ] Exclusions defined
- [ ] Initial baseline created
- [ ] Service/task configured
- [ ] Monitoring verified
- [ ] Logs rotating properly
- [ ] Alerts working
- [ ] Backup procedures established
- [ ] Documentation updated
- [ ] Team trained

---

**Version:** 1.0  
**Last Updated:** February 2026
