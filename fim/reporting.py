"""Console rendering of integrity-check results."""

from collections import defaultdict
from datetime import datetime
from typing import Dict

from .models import ChangeEvent
from .scanner import HAS_PSUTIL

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore


def print_security_findings(event: ChangeEvent, indent: str = '     ') -> None:
    """Render security findings attached to a single change event."""
    if not event.details:
        return
    d = event.details
    if d.get('honeypot'):
        print(f"{indent}🍯 HONEYPOT TRIPPED")
        if d.get('honeypot_alert'):
            print(f"{indent}   {d['honeypot_alert']}")
    if d.get('ransomware_indicator'):
        print(f"{indent}🚨 Part of suspected ransomware activity")
    if d.get('ransomware_extension'):
        print(f"{indent}🚨 Ransomware-associated extension: "
              f"{d['ransomware_extension']}")
    if 'entropy' in d:
        ent = d['entropy']
        tag = ' (HIGH — likely encrypted)' if d.get('entropy_alert') else ''
        print(f"{indent}🔢 Entropy: {ent}{tag}")
    if d.get('yara_matches'):
        print(f"{indent}🧬 YARA matches: {', '.join(d['yara_matches'])}")
    if d.get('signature'):
        sig = d['signature']
        status = sig.get('status') or 'unknown'
        signer = sig.get('signer') or '<unsigned>'
        valid_tag = '✅' if sig.get('valid') else '❌'
        print(f"{indent}🔏 Signature: {valid_tag} {status} — {signer}")
    if d.get('process'):
        p = d['process']
        print(f"{indent}👤 Process: PID {p.get('pid')} {p.get('name')} "
              f"(user: {p.get('user')})")


def generate_report(changes: Dict, scan_stats: Dict) -> bool:
    """Print the integrity-check report. Returns True if changes were detected."""
    print("\n" + "=" * 70)
    print(f"INTEGRITY CHECK REPORT - "
          f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    total_changes = (len(changes['modified']) + len(changes['added']) +
                     len(changes['deleted']))

    if total_changes == 0:
        print("\n✓ NO CHANGES DETECTED")
        print("  All files match baseline - system integrity verified")
    else:
        print(f"\n⚠ WARNING: {total_changes} CHANGE(S) DETECTED")

        if changes['modified']:
            print(f"\n🔴 MODIFIED FILES: {len(changes['modified'])}")
            for event in sorted(
                    changes['modified'],
                    key=lambda x: (0 if x.severity == 'critical' else
                                   1 if x.severity == 'high' else 2)):
                icon = "🔥" if event.severity == 'critical' else "⚠️"
                print(f"\n  {icon} {event.file_path}")
                print(f"     Severity: {event.severity.upper()}")
                print(f"     Old Hash: {event.old_hash[:16]}...")
                print(f"     New Hash: {event.new_hash[:16]}...")
                print(f"     Size: {event.old_size} → {event.new_size} bytes")
                if event.details and 'size_change' in event.details:
                    sc = event.details['size_change']
                    print(f"     Change: {'+' if sc >= 0 else ''}{sc} bytes")
                print_security_findings(event)

        if changes['added']:
            print(f"\n🟢 NEW FILES: {len(changes['added'])}")
            for event in changes['added'][:20]:
                print(f"\n  • {event.file_path}")
                print(f"    Hash: {event.new_hash[:16]}...")
                print(f"    Size: {event.new_size} bytes")
                print(f"    Severity: {event.severity}")
                print_security_findings(event, indent='    ')
            if len(changes['added']) > 20:
                print(f"\n  ... and {len(changes['added']) - 20} more")

        if changes['deleted']:
            print(f"\n🔵 DELETED FILES: {len(changes['deleted'])}")
            for event in changes['deleted'][:20]:
                print(f"\n  • {event.file_path}")
                print(f"    Severity: {event.severity}")
                print_security_findings(event, indent='    ')
            if len(changes['deleted']) > 20:
                print(f"\n  ... and {len(changes['deleted']) - 20} more")

    print(f"\n📊 SCAN STATISTICS:")
    print(f"  Files Scanned: {scan_stats.get('files_scanned', 0)}")
    print(f"  Scan Duration: {scan_stats.get('scan_duration', 0):.2f} seconds")
    print(f"  Changes Detected: {total_changes}")
    if HAS_PSUTIL and psutil is not None:
        print(f"  CPU Usage: {psutil.cpu_percent()}%")
        print(f"  Memory Usage: "
              f"{psutil.Process().memory_info().rss / 1024 / 1024:.2f} MB")
    print("\n" + "=" * 70)
    return total_changes > 0


def print_statistics(history, hours: int) -> None:
    """Print summary of recent change history."""
    print("\n" + "=" * 70)
    print(f"STATISTICS - Last {hours} Hours")
    print("=" * 70)

    if not history:
        print("\nNo changes recorded in the specified time period")
        return

    by_type = defaultdict(list)
    by_severity: Dict[str, int] = defaultdict(int)
    for event in history:
        by_type[event['event_type']].append(event)
        by_severity[event['severity']] += 1

    print(f"\nTotal Changes: {len(history)}")
    print(f"  Modified: {len(by_type['modified'])}")
    print(f"  Added: {len(by_type['added'])}")
    print(f"  Deleted: {len(by_type['deleted'])}")

    print(f"\nBy Severity:")
    for severity in ('critical', 'high', 'medium', 'low'):
        count = by_severity.get(severity, 0)
        if count > 0:
            print(f"  {severity.capitalize()}: {count}")

    print(f"\nRecent Changes (last 10):")
    for event in history[:10]:
        ts = datetime.fromisoformat(event['timestamp']).strftime(
            '%Y-%m-%d %H:%M:%S')
        print(f"\n  [{ts}] {event['event_type'].upper()}")
        print(f"    File: {event['file_path']}")
        print(f"    Severity: {event['severity']}")
    print("\n" + "=" * 70)
