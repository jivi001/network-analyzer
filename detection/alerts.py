"""
Alert Queue Manager for my-sentinel.
"""
import threading
import time
from datetime import datetime
from collections import defaultdict
from typing import List, Dict
from storage.models import AlertInfo


class AlertManager:
    """Manages alert deduplication and storage."""

    def __init__(self, max_alerts: int = 100, dedup_window: int = 60):
        self.lock = threading.Lock()
        self.max_alerts = max_alerts
        self.dedup_window = dedup_window

        self.alerts: List[AlertInfo] = []
        self.alert_counter = 0

        # Deduplication state: fingerprint -> float timestamp
        self.recent_fingerprints: Dict[str, float] = {}

    def _get_fingerprint(self, alert: AlertInfo) -> str:
        return f"{alert.rule_name}_{alert.src_ip}_{alert.dst_ip}"

    def add(self, alert: AlertInfo) -> bool:
        """Add alert if not duplicate, returns True if added."""
        with self.lock:
            fingerprint = self._get_fingerprint(alert)
            current_ts = alert.timestamp if isinstance(alert.timestamp, (int, float)) and alert.timestamp > 0 else time.time()

            if not alert.timestamp_str:
                dt = datetime.fromtimestamp(current_ts)
                alert.timestamp_str = dt.strftime("%H:%M:%S")

            # Check deduplication
            if fingerprint in self.recent_fingerprints:
                last_ts = self.recent_fingerprints[fingerprint]
                if current_ts - last_ts < self.dedup_window:
                    return False

            # Add alert
            self.recent_fingerprints[fingerprint] = current_ts
            self.alert_counter += 1
            alert.id = self.alert_counter

            self.alerts.append(alert)

            # Trim if exceeded max capacity
            if len(self.alerts) > self.max_alerts:
                self.alerts.pop(0)

            return True

    def get_recent(self, n: int = 10) -> List[AlertInfo]:
        """Get N most recent alerts."""
        with self.lock:
            return list(self.alerts[-n:])

    def get_all(self) -> List[AlertInfo]:
        """Get all alerts."""
        with self.lock:
            return list(self.alerts)

    def get_by_severity(self, severity: str) -> List[AlertInfo]:
        """Get alerts by severity."""
        with self.lock:
            return [a for a in self.alerts if a.severity.upper() == severity.upper()]

    def get_count(self) -> int:
        """Get total number of alerts."""
        with self.lock:
            return len(self.alerts)

    def clear(self):
        """Clear all alerts."""
        with self.lock:
            self.alerts.clear()
            self.recent_fingerprints.clear()

    def get_counts_by_severity(self) -> Dict[str, int]:
        """Get count of alerts grouped by severity."""
        with self.lock:
            counts = defaultdict(int)
            for a in self.alerts:
                counts[a.severity] += 1
            return dict(counts)
