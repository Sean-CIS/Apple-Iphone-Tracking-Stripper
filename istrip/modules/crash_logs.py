"""Crash reports and diagnostic log stripping."""

import logging

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.crash_reports import CrashReportsManager

log = logging.getLogger("istrip")


class CrashLogStripper:
    """Pulls and clears crash reports and diagnostic data from the device."""

    def __init__(self, lockdown: LockdownClient):
        self.lockdown = lockdown

    def list_reports(self) -> list[str]:
        """List all crash report filenames on device."""
        try:
            mgr = CrashReportsManager(self.lockdown)
            entries = mgr.ls("/")
            all_files = []
            for entry in entries:
                try:
                    sub = mgr.ls(f"/{entry}")
                    for s in sub:
                        all_files.append(f"{entry}/{s}")
                except Exception:
                    all_files.append(entry)
            return all_files
        except Exception as exc:
            log.error("Failed to list crash reports: %s", exc)
            return []

    def pull_reports(self, dest_dir: str) -> int:
        """Download all crash reports to a local directory for analysis."""
        try:
            mgr = CrashReportsManager(self.lockdown)
            mgr.pull(dest_dir)
            log.info("Crash reports pulled to %s", dest_dir)
            return len(self.list_reports())
        except Exception as exc:
            log.error("Failed to pull crash reports: %s", exc)
            return 0

    def clear_all(self) -> bool:
        """Delete all crash reports and diagnostic logs from the device."""
        try:
            mgr = CrashReportsManager(self.lockdown)
            mgr.clear()
            log.info("All crash reports and diagnostic logs cleared.")
            return True
        except Exception as exc:
            log.error("Failed to clear crash reports: %s", exc)
            return False

    def get_report_count(self) -> int:
        """Return the number of crash/diagnostic files on device."""
        return len(self.list_reports())
