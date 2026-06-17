#!/usr/bin/env python3
"""Backward-compatible entry point.

The implementation has been split into the ``fim`` package; this file
preserves the original ``python enterprise_fim.py ...`` invocation by
delegating to ``fim.cli.main()`` and re-exporting the public classes
so any external code importing from this module still works.
"""

import sys

from fim.cli import main
from fim.models import FileMetadata, ChangeEvent
from fim.config import ConfigManager, DEFAULT_CONFIG
from fim.log_handlers import JSONLogger
from fim.database import DatabaseManager
from fim.security import SecurityAnalyzer
from fim.scanner import FileScanner, HAS_PSUTIL
from fim.monitor import EnterpriseFileIntegrityMonitor
from fim.utils import clean_path as _clean_path, enable_utf8_stdout as _enable_utf8_stdout

__all__ = [
    'FileMetadata', 'ChangeEvent',
    'ConfigManager', 'DEFAULT_CONFIG',
    'JSONLogger', 'DatabaseManager',
    'SecurityAnalyzer', 'FileScanner',
    'EnterpriseFileIntegrityMonitor',
    'HAS_PSUTIL', 'main',
    '_clean_path', '_enable_utf8_stdout',
]


if __name__ == '__main__':
    sys.exit(main())
