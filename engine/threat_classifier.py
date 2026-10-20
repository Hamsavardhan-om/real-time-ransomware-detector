"""
Threat Level Classification Engine (Block 7).

Categorizes fused threat scores into the 5 discrete threat levels
specified in the architecture diagram:
- 0 - 20:   Low / Normal      (Color: Green)
- 21 - 50:  Medium / Watch    (Color: Yellow)
- 51 - 80:  High / Warning    (Color: Orange)
- 81 - 100: Critical / Attack (Color: Red)
- 100+:     Malicious / Block (Color: Dark Red)
"""

from dataclasses import dataclass
from typing import Tuple


@dataclass
class ThreatLevel:
    code: str           # LOW, MEDIUM, HIGH, CRITICAL, MALICIOUS
    label: str          # e.g., "Critical / Attack"
    color: str          # e.g., "red", "green", "yellow", "orange", "bold red"
    min_score: float
    max_score: float
    default_action: str # LOG_ONLY, ALERT, ISOLATE, KILL


LEVELS = [
    ThreatLevel("LOW", "Low / Normal", "green", 0.0, 20.0, "LOG_ONLY"),
    ThreatLevel("MEDIUM", "Medium / Watch", "yellow", 21.0, 50.0, "LOG_ONLY"),
    ThreatLevel("HIGH", "High / Warning", "orange3", 51.0, 80.0, "ALERT_PROMPT"),
    ThreatLevel("CRITICAL", "Critical / Attack", "bold red", 81.0, 100.0, "ISOLATE"),
    ThreatLevel("MALICIOUS", "Malicious / Block", "bold white on red", 100.0, float("inf"), "KILL"),
]


def classify_threat_level(score: float) -> ThreatLevel:
    """Classifies a numerical threat score into a ThreatLevel object."""
    if score >= 100.0:
        return LEVELS[4]
    elif score >= 81.0:
        return LEVELS[3]
    elif score >= 51.0:
        return LEVELS[2]
    elif score >= 21.0:
        return LEVELS[1]
    else:
        return LEVELS[0]
