"""Enterprise File Integrity Monitor (FIM) package.

Public API re-exports the main classes so callers can do:

    from fim import EnterpriseFileIntegrityMonitor, ConfigManager
"""

from fim.models import FileMetadata, ChangeEvent
from fim.config import ConfigManager, DEFAULT_CONFIG
from fim.log_handlers import JSONLogger
from fim.database import DatabaseManager
from fim.security import SecurityAnalyzer
from fim.scanner import FileScanner, HAS_PSUTIL
from fim.monitor import EnterpriseFileIntegrityMonitor

__all__ = [
    'FileMetadata',
    'ChangeEvent',
    'ConfigManager',
    'DEFAULT_CONFIG',
    'JSONLogger',
    'DatabaseManager',
    'SecurityAnalyzer',
    'FileScanner',
    'EnterpriseFileIntegrityMonitor',
    'HAS_PSUTIL',
]

__version__ = '2.0.0'
