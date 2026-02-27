"""
Syslog monitoring — watch device logs in real-time for tracking activity.
Identifies analytics events, location pings, ad SDK activity, and telemetry.
"""

import logging
import re
import threading
import time
from collections import defaultdict

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.os_trace import OsTraceService

log = logging.getLogger("istrip")

# Patterns that indicate tracking/analytics activity in syslog
TRACKING_PATTERNS = {
    "analytics": [
        re.compile(r"analyticsd", re.IGNORECASE),
        re.compile(r"AnalyticsEvent", re.IGNORECASE),
        re.compile(r"DiagnosticData", re.IGNORECASE),
        re.compile(r"UsageTracking", re.IGNORECASE),
        re.compile(r"AppMeasurement", re.IGNORECASE),
        re.compile(r"firebase.*analytics", re.IGNORECASE),
    ],
    "location": [
        re.compile(r"locationd.*significant", re.IGNORECASE),
        re.compile(r"CLLocationManager", re.IGNORECASE),
        re.compile(r"GeoFenc", re.IGNORECASE),
        re.compile(r"location.*report", re.IGNORECASE),
        re.compile(r"routined", re.IGNORECASE),
    ],
    "advertising": [
        re.compile(r"AdServices", re.IGNORECASE),
        re.compile(r"AdSupport", re.IGNORECASE),
        re.compile(r"ATTrackingManager", re.IGNORECASE),
        re.compile(r"personalized.*ad", re.IGNORECASE),
        re.compile(r"IDFA", re.IGNORECASE),
        re.compile(r"iad\b", re.IGNORECASE),
    ],
    "telemetry": [
        re.compile(r"telemetry", re.IGNORECASE),
        re.compile(r"metrics.*submit", re.IGNORECASE),
        re.compile(r"beacon.*send", re.IGNORECASE),
        re.compile(r"crashreport", re.IGNORECASE),
        re.compile(r"sysdiagnose", re.IGNORECASE),
    ],
    "network_tracking": [
        re.compile(r"doubleclick", re.IGNORECASE),
        re.compile(r"googlesyndication", re.IGNORECASE),
        re.compile(r"facebook.*pixel", re.IGNORECASE),
        re.compile(r"appsflyer", re.IGNORECASE),
        re.compile(r"adjust\.com", re.IGNORECASE),
        re.compile(r"branch\.io", re.IGNORECASE),
        re.compile(r"amplitude", re.IGNORECASE),
        re.compile(r"mixpanel", re.IGNORECASE),
        re.compile(r"segment\.io", re.IGNORECASE),
    ],
}


class SyslogMonitor:
    """
    Monitor device syslog in real-time to detect and report tracking activity.
    """

    def __init__(self, lockdown: LockdownClient):
        self.lockdown = lockdown
        self.findings: dict[str, list[str]] = defaultdict(list)
        self._stop_event = threading.Event()

    def monitor(self, duration: int = 30, callback=None) -> dict:
        """
        Monitor syslog for `duration` seconds, classifying tracking events.

        Args:
            duration: Seconds to monitor.
            callback: Optional callable(category, message, process) for each finding.

        Returns:
            Dict of category -> list of log messages that matched.
        """
        self.findings.clear()
        self._stop_event.clear()

        try:
            service = OsTraceService(self.lockdown)
        except Exception as exc:
            log.error("Failed to start syslog monitoring: %s", exc)
            return dict(self.findings)

        start = time.time()

        def _monitor():
            try:
                for entry in service.syslog():
                    if self._stop_event.is_set():
                        break
                    if time.time() - start > duration:
                        break

                    msg = str(entry)
                    for category, patterns in TRACKING_PATTERNS.items():
                        for pattern in patterns:
                            if pattern.search(msg):
                                short = msg[:200]
                                self.findings[category].append(short)
                                if callback:
                                    callback(category, short, "")
                                break
            except Exception:
                pass

        thread = threading.Thread(target=_monitor, daemon=True)
        thread.start()
        thread.join(timeout=duration + 5)
        self._stop_event.set()

        return dict(self.findings)

    def stop(self):
        """Stop ongoing monitoring."""
        self._stop_event.set()

    def get_summary(self) -> dict:
        """Return a summary count per category."""
        return {cat: len(msgs) for cat, msgs in self.findings.items()}
