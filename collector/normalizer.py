import math
import os
from typing import Dict, Any, Optional

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculates the Shannon Entropy (0.0 - 8.0) of a byte sequence."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    for count in byte_counts:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def sample_file_entropy(path: Optional[str], sample_size: int = 4096) -> float:
    """Reads a sample of bytes from the file to calculate Shannon entropy."""
    if not path or not os.path.exists(path) or os.path.isdir(path):
        return 0.0
    try:
        with open(path, "rb") as f:
            chunk = f.read(sample_size)
            return calculate_shannon_entropy(chunk)
    except Exception:
        return 0.0

class EventNormalizer:
    """
    Normalizes raw kernel telemetry events to 100% conform to Member 2's
    RansomShield NormalizedEvent schema.
    """
    def __init__(self, compute_entropy: bool = True):
        self.compute_entropy = compute_entropy

    def normalize(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Enriches and standardizes an event dictionary."""
        event_type = str(raw_event.get("event_type", "OTHER")).upper()
        path = raw_event.get("path") or None
        extra = raw_event.get("extra", {})

        # If file write, optionally calculate header entropy
        if self.compute_entropy and event_type == "FILE_WRITE" and path:
            entropy_val = sample_file_entropy(path)
            extra["entropy"] = entropy_val

        normalized = {
            "timestamp": float(raw_event.get("timestamp", 0.0)),
            "pid": int(raw_event.get("pid", 0)),
            "ppid": int(raw_event.get("ppid", 0)),
            "process": str(raw_event.get("process", "unknown")),
            "exe": str(raw_event.get("exe", raw_event.get("process", "unknown"))),
            "event_type": event_type,
            "path": path,
            "bytes": int(raw_event.get("bytes", 0)),
            "dst_ip": raw_event.get("dst_ip"),
            "dst_port": int(raw_event["dst_port"]) if raw_event.get("dst_port") is not None else None,
            "protocol": raw_event.get("protocol"),
            "success": bool(raw_event.get("success", True)),
            "extra": extra
        }
        return normalized
