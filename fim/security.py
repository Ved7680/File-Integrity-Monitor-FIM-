"""Security and threat-detection features layered on top of FIM.

Provides:
  1. Entropy analysis (Shannon entropy on file contents)
  2. YARA rule scanning (optional, requires yara-python)
  3. Digital signature verification (Windows PE files via PowerShell)
  4. Ransomware detection heuristics (bulk patterns, suspicious extensions)
  5. Honeypot file tracking (any change is critical)
  6. Process attribution (best-effort via psutil open_files)
"""

import math
import os
import platform
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .config import ConfigManager
    from .log_handlers import JSONLogger
    from .models import ChangeEvent

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

class SecurityAnalyzer:
    """Aggregates per-file and per-batch security checks."""

    # Extensions strongly associated with ransomware payloads.
    RANSOMWARE_EXTENSIONS = {
        '.encrypted', '.locked', '.crypt', '.crypted', '.enc', '.locky',
        '.zepto', '.cerber', '.cryptolocker', '.wcry', '.wncry', '.wnry',
        '.crypz', '.cryp1', '.osiris', '.aesir', '.zzzzz', '.xxx', '.ttt',
        '.micro', '.vault', '.ezz', '.exx', '.ecc', '.r5a', '.cry',
        '.kraken', '.darkness', '.nochance', '.crinf', '.r4a', '.scl',
        '.code', '.ctbl', '.ha3', '.toxcrypt', '.magic', '.thor', '.aaa',
        '.abc', '.xyz', '.pzdc', '.crypto', '.ryk', '.ryuk', '.conti',
        '.lockbit', '.makop', '.phobos', '.dharma'
    }

    ENTROPY_THRESHOLD_HIGH = 7.5
    ENTROPY_THRESHOLD_MED = 6.5

    SIGNED_EXTENSIONS = {'.exe', '.dll', '.sys', '.ocx', '.cab', '.cat',
                         '.msi', '.ps1', '.psm1', '.appx'}

    def __init__(self, config: 'ConfigManager', logger: 'JSONLogger'):
        self.config = config
        self.logger = logger
        sec = config.get('security', {}) or {}

        self.enable_entropy = sec.get('enable_entropy_analysis', True)
        self.enable_yara = sec.get('enable_yara_scanning', False)
        self.enable_signature = sec.get('enable_signature_verification', True)
        self.enable_ransomware = sec.get('enable_ransomware_detection', True)
        self.enable_honeypot = sec.get('enable_honeypot', True)
        self.enable_process_attr = sec.get('enable_process_attribution', True)

        self.entropy_sample_bytes = int(sec.get('entropy_sample_bytes', 1048576))
        self.ransomware_score_threshold = int(sec.get('ransomware_score_threshold', 50))
        self.ransomware_bulk_threshold = int(sec.get('ransomware_bulk_threshold', 10))

        self.honeypot_files = {
            os.path.normcase(os.path.normpath(os.path.abspath(p)))
            for p in sec.get('honeypot_files', [])
        }

        self.yara_rules = None
        if self.enable_yara:
            self._load_yara_rules(sec.get('yara_rules_directory', 'yara_rules'))

    # --- YARA ---------------------------------------------------------------
    def _load_yara_rules(self, rules_dir: str) -> None:
        try:
            import yara  # type: ignore
        except ImportError:
            self.logger.log_system('warning',
                'yara-python not installed; YARA scanning disabled. '
                'Install with: pip install yara-python')
            self.enable_yara = False
            return

        rules_path = Path(rules_dir)
        if not rules_path.exists():
            rules_path.mkdir(parents=True, exist_ok=True)
            self.logger.log_system('info', f'Created YARA rules directory: {rules_dir}')
            return

        rule_files = sorted(list(rules_path.glob('*.yar')) +
                            list(rules_path.glob('*.yara')))
        if not rule_files:
            self.logger.log_system('info', 'No YARA rule files found',
                                   directory=str(rules_path))
            return

        try:
            filepaths = {f.stem: str(f) for f in rule_files}
            self.yara_rules = yara.compile(filepaths=filepaths)
            self.logger.log_system('info',
                f'Compiled {len(rule_files)} YARA rule file(s)',
                directory=str(rules_path))
        except Exception as e:  # noqa: BLE001
            self.logger.log_system('error', 'YARA compile failed', error=str(e))
            self.enable_yara = False

    def scan_yara(self, filepath: str) -> List[str]:
        if not self.enable_yara or self.yara_rules is None:
            return []
        try:
            matches = self.yara_rules.match(filepath, timeout=10)
            return [str(m) for m in matches]
        except Exception as e:  # noqa: BLE001
            self.logger.log_system('warning', f'YARA scan failed: {filepath}',
                                   error=str(e))
            return []

    # --- 1. Entropy analysis ------------------------------------------------
    def calculate_entropy(self, filepath: str) -> Optional[float]:
        """Shannon entropy (0-8) on up to ``entropy_sample_bytes`` of the file."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(self.entropy_sample_bytes)
            if not data:
                return 0.0
            freq = [0] * 256
            for byte in data:
                freq[byte] += 1
            length = len(data)
            entropy = 0.0
            for count in freq:
                if count == 0:
                    continue
                p = count / length
                entropy -= p * math.log2(p)
            return round(entropy, 3)
        except (OSError, PermissionError):
            return None

    # --- 3. Signature verification ------------------------------------------
    def verify_signature(self, filepath: str) -> Dict:
        """Verify Authenticode signature on Windows binaries."""
        result = {'checked': False, 'valid': None,
                  'signer': None, 'status': None}
        if not self.enable_signature:
            return result

        ext = os.path.splitext(filepath)[1].lower()
        if ext not in self.SIGNED_EXTENSIONS:
            return result
        if platform.system() != 'Windows':
            return result

        try:
            ps_cmd = (
                "$ErrorActionPreference='Stop';"
                f"$s = Get-AuthenticodeSignature -LiteralPath {self._ps_quote(filepath)};"
                "$subj = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' };"
                "Write-Output (\"{0}|{1}\" -f $s.Status, $subj)"
            )
            proc = subprocess.run(
                ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps_cmd],
                capture_output=True, text=True, timeout=20
            )
            if proc.returncode == 0 and proc.stdout.strip():
                line = proc.stdout.strip().splitlines()[-1]
                if '|' in line:
                    status, signer = line.split('|', 1)
                    result['checked'] = True
                    result['status'] = status.strip()
                    result['signer'] = signer.strip() or None
                    result['valid'] = (result['status'] == 'Valid')
        except subprocess.TimeoutExpired:
            self.logger.log_system('warning',
                f'Signature check timed out: {filepath}')
        except Exception as e:  # noqa: BLE001
            self.logger.log_system('warning',
                f'Signature check failed: {filepath}', error=str(e))
        return result

    @staticmethod
    def _ps_quote(s: str) -> str:
        return "'" + s.replace("'", "''") + "'"

    # --- 4. Ransomware heuristic --------------------------------------------
    def detect_ransomware(self, events: List['ChangeEvent']) -> Optional[Dict]:
        if not self.enable_ransomware or not events:
            return None

        suspicious_ext: List[str] = []
        high_entropy = 0
        modified = 0
        added = 0

        for ev in events:
            ext = os.path.splitext(ev.file_path)[1].lower()
            if ext in self.RANSOMWARE_EXTENSIONS:
                suspicious_ext.append(ev.file_path)
            if ev.event_type == 'modified':
                modified += 1
            elif ev.event_type == 'added':
                added += 1
            if ev.details and isinstance(ev.details, dict):
                ent = ev.details.get('entropy')
                if isinstance(ent, (int, float)) and ent >= self.ENTROPY_THRESHOLD_HIGH:
                    high_entropy += 1

        score = 0
        reasons: List[str] = []
        if len(suspicious_ext) >= 3:
            score += 50
            reasons.append(f'{len(suspicious_ext)} files with ransomware-associated extensions')
        if high_entropy >= 5:
            score += 30
            reasons.append(f'{high_entropy} modified files with high entropy (likely encrypted)')
        if modified >= self.ransomware_bulk_threshold:
            score += 20
            reasons.append(f'{modified} files modified in a single scan')
        if added >= self.ransomware_bulk_threshold and suspicious_ext:
            score += 25
            reasons.append('Bulk new files with ransomware-associated extensions')

        if score < self.ransomware_score_threshold:
            return None

        return {
            'detected': True,
            'score': score,
            'reasons': reasons,
            'suspicious_files': suspicious_ext[:20],
            'high_entropy_count': high_entropy,
            'bulk_modified': modified,
            'bulk_added': added,
        }

    # --- 5. Honeypots --------------------------------------------------------
    def is_honeypot(self, abs_path: str) -> bool:
        if not self.enable_honeypot or not self.honeypot_files:
            return False
        norm = os.path.normcase(os.path.normpath(os.path.abspath(abs_path)))
        return norm in self.honeypot_files

    def deploy_honeypots(self, directory: str,
                         names: Optional[List[str]] = None) -> List[str]:
        directory = Path(directory).resolve()
        directory.mkdir(parents=True, exist_ok=True)
        if names is None:
            names = ['passwords.txt', 'private_keys.pem',
                     'employee_records.csv', 'banking_info.docx',
                     'api_keys.json']
        deployed: List[str] = []
        for name in names:
            target = directory / name
            if target.exists():
                continue
            target.write_text(self._honeypot_content(name), encoding='utf-8')
            deployed.append(str(target.resolve()))

        if deployed:
            existing = list(self.config.get('security.honeypot_files', []) or [])
            updated = list({*existing, *deployed})
            self.config.set('security.honeypot_files', updated)
            self.honeypot_files |= {
                os.path.normcase(os.path.normpath(p)) for p in deployed
            }
            self.logger.log_system('info',
                f'Deployed {len(deployed)} honeypot file(s)',
                directory=str(directory), files=deployed)
        return deployed

    @staticmethod
    def _honeypot_content(name: str) -> str:
        lower = name.lower()
        if 'password' in lower:
            return ("# Internal credential vault - DO NOT DISTRIBUTE\n"
                    "admin_user: <redacted>\n"
                    "db_root: <redacted>\n"
                    "vpn_shared: <redacted>\n")
        if 'key' in lower:
            return ("-----BEGIN RSA PRIVATE KEY-----\n"
                    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ== <fake>\n"
                    "-----END RSA PRIVATE KEY-----\n")
        if 'banking' in lower:
            return "Account,Routing,Balance\n0001,000000000,0.00\n"
        if 'employee' in lower or 'records' in lower:
            return "id,name,ssn,salary\n0,EXAMPLE,000-00-0000,0\n"
        if 'api' in lower:
            return ('{"aws_access_key_id": "AKIA0000FAKE", '
                    '"aws_secret_access_key": "FAKE"}\n')
        return f"Internal document: {name}\n[REDACTED]\n"

    # --- 6. Process attribution ---------------------------------------------
    def attribute_process(self, abs_path: str) -> Optional[Dict]:
        if not self.enable_process_attr or not HAS_PSUTIL:
            return None
        try:
            target = os.path.normcase(os.path.normpath(os.path.abspath(abs_path)))
            for proc in psutil.process_iter(['pid', 'name', 'username']):
                try:
                    open_files = proc.open_files()
                except (psutil.AccessDenied, psutil.NoSuchProcess,
                        psutil.ZombieProcess):
                    continue
                for of in open_files:
                    if os.path.normcase(os.path.normpath(of.path)) == target:
                        return {
                            'pid': proc.info.get('pid'),
                            'name': proc.info.get('name'),
                            'user': proc.info.get('username'),
                        }
        except Exception:  # noqa: BLE001
            return None
        return None

    # --- Aggregate per-file analysis ----------------------------------------
    def analyze_file(self, abs_path: str,
                     rel_path: Optional[str] = None) -> Dict:
        """Run all enabled per-file checks and return a dict of findings."""
        analysis: Dict = {}
        display_path = rel_path or abs_path

        if self.enable_entropy:
            entropy = self.calculate_entropy(abs_path)
            if entropy is not None:
                analysis['entropy'] = entropy
                if entropy >= self.ENTROPY_THRESHOLD_HIGH:
                    analysis['entropy_alert'] = 'high (likely encrypted/compressed)'

        if self.enable_yara:
            matches = self.scan_yara(abs_path)
            if matches:
                analysis['yara_matches'] = matches

        if self.enable_signature:
            sig = self.verify_signature(abs_path)
            if sig.get('checked'):
                analysis['signature'] = sig
                if sig.get('valid') is False:
                    analysis['signature_alert'] = sig.get('status')

        if self.enable_process_attr:
            proc = self.attribute_process(abs_path)
            if proc:
                analysis['process'] = proc

        ext = os.path.splitext(display_path)[1].lower()
        if ext in self.RANSOMWARE_EXTENSIONS:
            analysis['ransomware_extension'] = ext

        return analysis

    @staticmethod
    def derive_severity(base_severity: str, analysis: Dict,
                        is_honeypot: bool = False) -> str:
        """Promote severity based on security findings."""
        order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        rank = order.get(base_severity, 1)

        if is_honeypot:
            rank = max(rank, order['critical'])
        if analysis.get('yara_matches'):
            rank = max(rank, order['critical'])
        if analysis.get('ransomware_extension'):
            rank = max(rank, order['critical'])
        if analysis.get('entropy_alert'):
            rank = max(rank, order['high'])
        if analysis.get('signature_alert'):
            rank = max(rank, order['high'])

        return [k for k, v in order.items() if v == rank][0]
