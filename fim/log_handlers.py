"""Structured JSON logging for FIM events, alerts, system, and performance."""

import json
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Dict

from .models import ChangeEvent


class JSONLogger:
    """Routes FIM messages to four separate JSON-formatted rotating files."""

    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.events_logger = self._setup_json_logger(
            'fim.events', self.log_dir / 'events.json')
        self.system_logger = self._setup_json_logger(
            'fim.system', self.log_dir / 'system.json')
        self.alerts_logger = self._setup_json_logger(
            'fim.alerts', self.log_dir / 'alerts.json')
        self.performance_logger = self._setup_json_logger(
            'fim.performance', self.log_dir / 'performance.json')

    @staticmethod
    def _setup_json_logger(name: str, filepath: Path) -> logging.Logger:
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        logger.propagate = False

        # Avoid attaching duplicate handlers when the package is re-imported.
        for h in list(logger.handlers):
            logger.removeHandler(h)

        handler = RotatingFileHandler(
            filepath,
            maxBytes=10 * 1024 * 1024,
            backupCount=10,
            encoding='utf-8'
        )
        handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(handler)
        return logger

    def log_event(self, event: ChangeEvent) -> None:
        event_data = {
            "timestamp": event.timestamp,
            "event_type": event.event_type,
            "file_path": event.file_path,
            "severity": event.severity,
            "old_hash": event.old_hash,
            "new_hash": event.new_hash,
            "old_size": event.old_size,
            "new_size": event.new_size,
            "details": event.details or {},
        }
        self.events_logger.info(json.dumps(event_data))
        if event.severity in ('high', 'critical'):
            self.log_alert(event_data)

    def log_alert(self, alert_data: Dict) -> None:
        alert_data = dict(alert_data)
        alert_data['alert_timestamp'] = datetime.now().isoformat()
        self.alerts_logger.warning(json.dumps(alert_data))

    def log_system(self, level: str, message: str, **kwargs) -> None:
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message,
            **kwargs,
        }
        self.system_logger.info(json.dumps(log_data))

    def log_performance(self, operation: str, duration: float, **metrics) -> None:
        perf_data = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            "duration_seconds": duration,
            **metrics,
        }
        self.performance_logger.info(json.dumps(perf_data))
