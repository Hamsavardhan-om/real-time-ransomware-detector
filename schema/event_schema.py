"""
RansomShield Telemetry Event Schema Definition.

Specifies the exact contract format exchanged between:
Box 1 (eBPF Kernel Sensor) -> Box 2 (Collector & Normalizer) -> Box 3 (JSON/JSONL Dataset) -> Member 2 (Behavioral AI Detector).
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, Dict, Any


class EventType(str, Enum):
    FILE_OPEN = "FILE_OPEN"
    FILE_READ = "FILE_READ"
    FILE_WRITE = "FILE_WRITE"
    FILE_CLOSE = "FILE_CLOSE"
    FILE_CREATE = "FILE_CREATE"
    FILE_DELETE = "FILE_DELETE"
    FILE_RENAME = "FILE_RENAME"
    PROCESS_EXEC = "PROCESS_EXEC"
    PROCESS_EXIT = "PROCESS_EXIT"
    NET_CONNECT = "NET_CONNECT"
    OTHER = "OTHER"


@dataclass
class NormalizedEvent:
    """
    Standard Normalized Telemetry Event.
    
    Attributes:
        timestamp: Unix epoch timestamp in seconds (float).
        pid: Operating system Process Identifier (int).
        ppid: Parent Process Identifier (int).
        process: Process command name / comm string (str).
        exe: Absolute path to process binary or executable name (str).
        event_type: One of EventType enum values (str).
        path: Target file path or directory path (str or None).
        bytes: I/O byte count for read/write events (int).
        dst_ip: Outbound destination IPv4 address (str or None).
        dst_port: Outbound destination TCP port (int or None).
        protocol: Network protocol e.g. 'TCP' (str or None).
        success: Whether the operation succeeded (bool).
        extra: Additional contextual metadata such as Shannon entropy or old_path (dict).
    """
    timestamp: float
    pid: int
    ppid: int
    process: str
    exe: str
    event_type: str
    path: Optional[str] = None
    bytes: int = 0
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    success: bool = True
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "NormalizedEvent":
        return cls(
            timestamp=float(data.get("timestamp", 0.0)),
            pid=int(data.get("pid", 0)),
            ppid=int(data.get("ppid", 0)),
            process=str(data.get("process", "unknown")),
            exe=str(data.get("exe", data.get("process", "unknown"))),
            event_type=str(data.get("event_type", "OTHER")).upper(),
            path=data.get("path"),
            bytes=int(data.get("bytes", 0)),
            dst_ip=data.get("dst_ip"),
            dst_port=int(data["dst_port"]) if data.get("dst_port") is not None else None,
            protocol=data.get("protocol"),
            success=bool(data.get("success", True)),
            extra=data.get("extra") if isinstance(data.get("extra"), dict) else {},
        )
