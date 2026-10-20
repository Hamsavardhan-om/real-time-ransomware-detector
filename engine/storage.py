"""
RansomShield Persistent Storage Engine (Block 9B).

Maintains SQLite database (datasets/ransomshield.db) tracking:
1. Raw Events: [id, ts, pid, event_type, path, bytes, entropy]
2. Feature Windows: [id, window_id, pid, feature_vector, ts]
3. Threat Scores: [id, window_id, pid, process, rule_score, ai_score, final_score, threat_level, ts]
4. Alerts & Actions: [id, score_id, pid, process, level, action_taken, details, ts]
"""

import sqlite3
import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional


class RansomShieldStorage:
    def __init__(self, db_path: Optional[Path] = None):
        if db_path is None:
            project_root = Path(__file__).resolve().parent.parent
            self.db_path = project_root / "datasets" / "ransomshield.db"
        else:
            self.db_path = Path(db_path)

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._event_buffer = []
        self._last_flush = time.time()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initializes tables matching Block 9B in architecture diagram."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=DELETE;")
            cursor.execute("PRAGMA synchronous=NORMAL;")

            # 1. Raw Events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    pid INTEGER NOT NULL,
                    ppid INTEGER,
                    process TEXT,
                    event_type TEXT NOT NULL,
                    path TEXT,
                    bytes INTEGER DEFAULT 0,
                    entropy REAL DEFAULT 0.0
                )
            """)

            # 2. Features table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS features (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    window_id TEXT,
                    pid INTEGER NOT NULL,
                    feature_vector TEXT NOT NULL,
                    ts REAL NOT NULL
                )
            """)

            # 3. Threat Scores table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    window_id TEXT,
                    pid INTEGER NOT NULL,
                    process TEXT NOT NULL,
                    rule_score REAL NOT NULL,
                    ai_score REAL NOT NULL,
                    final_score REAL NOT NULL,
                    threat_level TEXT NOT NULL,
                    ts REAL NOT NULL
                )
            """)

            # 4. Alerts & Actions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    score_id INTEGER,
                    pid INTEGER NOT NULL,
                    process TEXT NOT NULL,
                    level TEXT NOT NULL,
                    action_taken TEXT NOT NULL,
                    details TEXT,
                    ts REAL NOT NULL
                )
            """)
            conn.commit()

    def flush_events(self):
        """Flushes buffered events to SQLite in a single transaction."""
        if not self._event_buffer:
            return
        to_insert = self._event_buffer
        self._event_buffer = []
        self._last_flush = time.time()
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.executemany("""
                    INSERT INTO events (ts, pid, ppid, process, event_type, path, bytes, entropy)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, to_insert)
                conn.commit()
        except Exception:
            pass

    def log_event(self, event: Dict[str, Any]):
        """Buffers and writes events in batches to ensure maximum throughput."""
        row = (
            float(event.get("timestamp", time.time())),
            int(event.get("pid", 0)),
            int(event.get("ppid", 0)),
            str(event.get("process", "unknown")),
            str(event.get("event_type", "OTHER")),
            event.get("path"),
            int(event.get("bytes", 0)),
            float(event.get("extra", {}).get("entropy", 0.0)),
        )
        self._event_buffer.append(row)
        if len(self._event_buffer) >= 20 or (time.time() - self._last_flush) > 0.5:
            self.flush_events()

    def log_threat_score(
        self,
        pid: int,
        process: str,
        rule_score: float,
        ai_score: float,
        final_score: float,
        threat_level: str,
        window_id: str = "",
    ) -> int:
        """Logs a computed threat assessment score and returns the row ID."""
        self.flush_events()
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO threat_scores (window_id, pid, process, rule_score, ai_score, final_score, threat_level, ts)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    window_id,
                    pid,
                    process,
                    rule_score,
                    ai_score,
                    final_score,
                    threat_level,
                    time.time(),
                ))
                conn.commit()
                return cursor.lastrowid
        except Exception:
            return 0

    def log_alert(
        self,
        pid: int,
        process: str,
        level: str,
        action_taken: str,
        details: str = "",
        score_id: Optional[int] = None,
    ) -> int:
        """Logs an action taken by the Decision Engine."""
        self.flush_events()
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO alerts (score_id, pid, process, level, action_taken, details, ts)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    score_id,
                    pid,
                    process,
                    level,
                    action_taken,
                    details,
                    time.time(),
                ))
                conn.commit()
                return cursor.lastrowid
        except Exception:
            return 0

    def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Fetches the latest alerts from the database."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM alerts ORDER BY id DESC LIMIT ?
                """, (limit,))
                rows = cursor.fetchall()
                return [dict(r) for r in rows]
        except Exception:
            return []

    def get_summary_stats(self) -> Dict[str, int]:
        """Returns total counts across tables."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM events")
                total_events = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM threat_scores")
                total_scores = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM alerts")
                total_alerts = cursor.fetchone()[0]
                return {
                    "events": total_events,
                    "threat_scores": total_scores,
                    "alerts": total_alerts,
                }
        except Exception:
            return {"events": 0, "threat_scores": 0, "alerts": 0}
