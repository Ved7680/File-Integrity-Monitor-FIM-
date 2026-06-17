"""Command-line interface for the FIM package."""

import argparse
import sys
from pathlib import Path

from .monitor import EnterpriseFileIntegrityMonitor
from .utils import clean_path, enable_utf8_stdout


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Enterprise File Integrity Monitor (FIM)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Create baseline:
    python -m fim --create-baseline /path/to/dir1 /path/to/dir2

  Single integrity check:
    python -m fim --check /path/to/directory

  Continuous monitoring:
    python -m fim --monitor /path/to/dir1 /path/to/dir2 --interval 60

  Show statistics:
    python -m fim --stats --hours 48

  Configure:
    python -m fim --config monitoring.scan_interval=120

  Security:
    python -m fim --security-status
    python -m fim --deploy-honeypots /path/to/dir
    python -m fim --add-honeypot /path/to/file
    python -m fim --list-honeypots
        """
    )

    parser.add_argument('--create-baseline', nargs='+', metavar='DIR',
                        help='Create baseline for specified directories')
    parser.add_argument('--check', metavar='DIR',
                        help='Check integrity of directory against baseline')
    parser.add_argument('--monitor', nargs='+', metavar='DIR',
                        help='Continuously monitor directories')
    parser.add_argument('--interval', type=int, default=60,
                        help='Scan interval in seconds for monitoring (default: 60)')
    parser.add_argument('--stats', action='store_true',
                        help='Show statistics and change history')
    parser.add_argument('--hours', type=int, default=24,
                        help='Hours of history to show in stats (default: 24)')
    parser.add_argument('--config', metavar='KEY=VALUE',
                        help='Set configuration value (e.g., monitoring.scan_interval=120)')
    parser.add_argument('--db', default='fim_database.db',
                        help='Database file path (default: fim_database.db)')
    parser.add_argument('--config-file', default='fim_config.json',
                        help='Configuration file path (default: fim_config.json)')
    parser.add_argument('--deploy-honeypots', metavar='DIR',
                        help='Deploy decoy honeypot files into DIR and register them')
    parser.add_argument('--add-honeypot', nargs='+', metavar='FILE',
                        help='Register existing file path(s) as honeypot(s)')
    parser.add_argument('--list-honeypots', action='store_true',
                        help='List all registered honeypot file paths')
    parser.add_argument('--security-status', action='store_true',
                        help='Show which security/detection features are enabled')
    return parser


def main(argv=None) -> int:
    enable_utf8_stdout()
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        fim = EnterpriseFileIntegrityMonitor(
            config_file=args.config_file,
            db_path=args.db,
        )

        if args.config:
            key, value = args.config.split('=', 1)
            try:
                import ast
                value = ast.literal_eval(value)
            except Exception:
                pass
            fim.config.set(key, value)
            print(f"Configuration updated: {key} = {value}")

        elif args.create_baseline:
            cleaned = [clean_path(d) for d in args.create_baseline]
            fim.create_baseline(cleaned)

        elif args.check:
            changes = fim.check_integrity(clean_path(args.check))
            if changes:
                fim.generate_report(changes)

        elif args.monitor:
            cleaned = [clean_path(d) for d in args.monitor]
            fim.monitor_continuous(cleaned, interval=args.interval)

        elif args.stats:
            fim.show_statistics(hours=args.hours)

        elif args.deploy_honeypots:
            deployed = fim.security.deploy_honeypots(
                clean_path(args.deploy_honeypots))
            if deployed:
                print(f"\n✓ Deployed {len(deployed)} honeypot file(s) in "
                      f"{args.deploy_honeypots}:")
                for p in deployed:
                    print(f"   • {p}")
                print("\nThese files are now tracked. Any modification or "
                      "deletion will trigger a CRITICAL alert.")
            else:
                print(f"\nNo new honeypots created (files may already exist) "
                      f"in {args.deploy_honeypots}")

        elif args.add_honeypot:
            existing = list(fim.config.get('security.honeypot_files', []) or [])
            new_paths = [str(Path(clean_path(p)).resolve())
                         for p in args.add_honeypot]
            updated = list({*existing, *new_paths})
            fim.config.set('security.honeypot_files', updated)
            print(f"✓ Registered {len(new_paths)} honeypot path(s).")
            for p in new_paths:
                print(f"   • {p}")

        elif args.list_honeypots:
            honeypots = fim.config.get('security.honeypot_files', []) or []
            if not honeypots:
                print("No honeypot files registered.")
            else:
                print(f"Registered honeypots ({len(honeypots)}):")
                for p in honeypots:
                    exists = "✓" if Path(p).exists() else "✗ MISSING"
                    print(f"   {exists}  {p}")

        elif args.security_status:
            sec = fim.security
            print("\n" + "=" * 70)
            print("SECURITY & DETECTION FEATURES")
            print("=" * 70)
            features = [
                ("Entropy analysis", sec.enable_entropy),
                ("YARA scanning", sec.enable_yara),
                ("Digital signature verification", sec.enable_signature),
                ("Ransomware detection heuristics", sec.enable_ransomware),
                ("Honeypot tracking", sec.enable_honeypot),
                ("Process attribution", sec.enable_process_attr),
            ]
            for name, on in features:
                mark = "✓ ENABLED " if on else "✗ disabled"
                print(f"  {mark}  {name}")
            print(f"\n  YARA rules loaded: "
                  f"{'yes' if sec.yara_rules else 'no'}")
            print(f"  Honeypots registered: {len(sec.honeypot_files)}")
            print(f"  Ransomware score threshold: "
                  f"{sec.ransomware_score_threshold}")
            print("=" * 70)

        else:
            parser.print_help()

        fim.cleanup()
        return 0

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        return 0
    except Exception as e:  # noqa: BLE001
        print(f"\nFatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
