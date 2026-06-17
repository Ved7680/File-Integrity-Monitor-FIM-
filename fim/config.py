"""Configuration management for the FIM package."""

import json
from pathlib import Path
from typing import Any, Dict


DEFAULT_CONFIG: Dict[str, Any] = {
    "monitoring": {
        "scan_interval": 60,
        "worker_threads": 4,
        "max_file_size_mb": 500,
        "enable_incremental_scan": True
    },
    "watch_directories": [],
    "exclude_patterns": [
        "*.tmp",
        "*.temp",
        "*.log",
        "*.swp",
        "*~",
        ".git/*",
        ".svn/*",
        "__pycache__/*",
        "node_modules/*",
        ".DS_Store"
    ],
    "priority_patterns": {
        "critical": ["*.exe", "*.dll", "*.sys", "*.bat", "*.ps1"],
        "high": ["*.conf", "*.config", "*.ini", "*.xml"],
        "medium": ["*.py", "*.js", "*.java", "*.cpp"]
    },
    "alerting": {
        "enable_email": False,
        "enable_webhook": False,
        "critical_file_patterns": ["*.exe", "/etc/passwd", "/etc/shadow"],
        "alert_threshold": 10
    },
    "performance": {
        "enable_caching": True,
        "cache_ttl_seconds": 300,
        "batch_size": 100
    },
    "logging": {
        "log_directory": "logs",
        "retention_days": 30,
        "max_log_size_mb": 100
    },
    "security": {
        "enable_entropy_analysis": True,
        "enable_yara_scanning": False,
        "enable_signature_verification": True,
        "enable_ransomware_detection": True,
        "enable_honeypot": True,
        "enable_process_attribution": False,
        "entropy_sample_bytes": 1048576,
        "ransomware_score_threshold": 50,
        "ransomware_bulk_threshold": 10,
        "yara_rules_directory": "yara_rules",
        "honeypot_files": []
    }
}


class ConfigManager:
    """JSON-file configuration with dot-notation get/set."""

    def __init__(self, config_file: str = "fim_config.json"):
        self.config_file = Path(config_file)
        self.config: Dict[str, Any] = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        if self.config_file.exists():
            with open(self.config_file, 'r', encoding='utf-8') as f:
                loaded = json.load(f)
            return self._merge_defaults(loaded, DEFAULT_CONFIG)
        self.save_config(DEFAULT_CONFIG)
        return json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy

    @staticmethod
    def _merge_defaults(loaded: Dict, defaults: Dict) -> Dict:
        """Recursively add any keys present in defaults but missing in loaded."""
        result = dict(loaded) if isinstance(loaded, dict) else {}
        for key, value in defaults.items():
            if key not in result:
                result[key] = value
            elif isinstance(value, dict) and isinstance(result[key], dict):
                result[key] = ConfigManager._merge_defaults(result[key], value)
        return result

    def save_config(self, config: Dict[str, Any]) -> None:
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        self.config = config

    def get(self, key_path: str, default: Any = None) -> Any:
        keys = key_path.split('.')
        value: Any = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value

    def set(self, key_path: str, value: Any) -> None:
        if self._apply(key_path, value):
            self.save_config(self.config)

    def set_many(self, updates: Dict[str, Any]) -> None:
        """Apply many dotted-key updates and save the config file once."""
        changed = False
        for key_path, value in updates.items():
            if self._apply(key_path, value):
                changed = True
        if changed:
            self.save_config(self.config)

    def _apply(self, key_path: str, value: Any) -> bool:
        """Write value into the in-memory config. Returns True if it changed."""
        keys = key_path.split('.')
        cfg = self.config
        for key in keys[:-1]:
            if key not in cfg or not isinstance(cfg[key], dict):
                cfg[key] = {}
            cfg = cfg[key]
        if cfg.get(keys[-1]) == value:
            return False
        cfg[keys[-1]] = value
        return True
