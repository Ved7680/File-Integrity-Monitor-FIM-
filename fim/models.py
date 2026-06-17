"""Data models used throughout the FIM package."""

from dataclasses import dataclass, asdict
from typing import Dict, Optional


@dataclass
class FileMetadata:
    """Structured snapshot of a single file at scan time."""
    path: str
    hash: str
    size: int
    modified_time: float
    created_time: float
    permissions: str
    owner: str
    inode: Optional[int] = None

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ChangeEvent:
    """Represents a single detected change between baseline and current state."""
    event_type: str  # 'modified' | 'added' | 'deleted'
    timestamp: str
    file_path: str
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    old_size: Optional[int] = None
    new_size: Optional[int] = None
    severity: str = 'medium'  # low | medium | high | critical
    details: Optional[Dict] = None

    def to_dict(self) -> Dict:
        return asdict(self)
