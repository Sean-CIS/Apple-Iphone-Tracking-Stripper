"""
Backup manipulation engine — the most powerful tracking removal vector.
Creates a device backup, modifies privacy-related databases and plists,
then restores the modified backup to enforce privacy settings.
"""

import hashlib
import logging
import os
import plistlib
import shutil
import sqlite3
import tempfile
import time
from pathlib import Path

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service

log = logging.getLogger("istrip")


# Backup domain/path -> description of what it controls
PRIVACY_TARGETS = {
    # TCC (Transparency, Consent, and Control) database — per-app permissions
    ("HomeDomain", "Library/TCC/TCC.db"): "App permission database (camera, mic, contacts, location, tracking)",
    # Safari preferences
    ("HomeDomain", "Library/Preferences/com.apple.mobilesafari.plist"): "Safari privacy settings",
    # General preferences
    ("HomeDomain", "Library/Preferences/com.apple.Preferences.plist"): "General device preferences",
    # Location services
    ("HomeDomain", "Library/Preferences/com.apple.locationd.plist"): "Location services configuration",
    # Analytics / diagnostics
    ("HomeDomain", "Library/Preferences/com.apple.DiagnosticDataSubmission.plist"): "Diagnostics sharing settings",
    # Advertising
    ("HomeDomain", "Library/Preferences/com.apple.AdLib.plist"): "Ad tracking preferences",
    ("HomeDomain", "Library/Preferences/com.apple.adsupport.plist"): "Ad support / IDFA settings",
    # Spotlight / Siri suggestions
    ("HomeDomain", "Library/Preferences/com.apple.Spotlight.plist"): "Spotlight suggestions & Siri data",
    # WiFi known networks (location inference)
    ("SystemPreferencesDomain", "SystemConfiguration/com.apple.wifi.plist"): "Known WiFi networks",
    # Cookies
    ("HomeDomain", "Library/Cookies/Cookies.binarycookies"): "Safari cookies",
}


def _domain_path_hash(domain: str, path: str) -> str:
    """Compute the SHA-1 hash used as the backup filename: SHA1(domain-path)."""
    raw = f"{domain}-{path}"
    return hashlib.sha1(raw.encode()).hexdigest()


class BackupEngine:
    """Perform backup-based deep tracking removal."""

    def __init__(self, lockdown: LockdownClient):
        self.lockdown = lockdown
        self.backup_dir: Path | None = None
        self.modifications: list[str] = []

    def create_backup(self, dest: str | None = None, progress_callback=None) -> bool:
        """
        Create a full device backup.

        Args:
            dest: Directory to store backup. Uses temp dir if None.
            progress_callback: Optional callable(message: str)
        """
        if dest:
            self.backup_dir = Path(dest)
        else:
            self.backup_dir = Path(tempfile.mkdtemp(prefix="istrip_backup_"))

        self.backup_dir.mkdir(parents=True, exist_ok=True)

        log.info("Starting full device backup to %s ...", self.backup_dir)
        if progress_callback:
            progress_callback("Starting backup — this may take several minutes...")

        try:
            backup_svc = Mobilebackup2Service(self.lockdown)
            backup_svc.backup(
                full=True,
                backup_directory=str(self.backup_dir),
                progress_callback=progress_callback or (lambda _: None),
            )
            log.info("Backup completed successfully.")
            if progress_callback:
                progress_callback("Backup complete.")
            return True
        except Exception as exc:
            log.error("Backup failed: %s", exc)
            if progress_callback:
                progress_callback(f"Backup failed: {exc}")
            return False

    def restore_backup(self, progress_callback=None) -> bool:
        """Restore the (modified) backup to the device."""
        if not self.backup_dir:
            log.error("No backup directory set.")
            return False

        log.info("Restoring modified backup from %s ...", self.backup_dir)
        if progress_callback:
            progress_callback("Restoring backup — device will restart after...")

        try:
            backup_svc = Mobilebackup2Service(self.lockdown)
            backup_svc.restore(
                backup_directory=str(self.backup_dir),
                progress_callback=progress_callback or (lambda _: None),
            )
            log.info("Restore completed.")
            if progress_callback:
                progress_callback("Restore complete. Device may restart.")
            return True
        except Exception as exc:
            log.error("Restore failed: %s", exc)
            if progress_callback:
                progress_callback(f"Restore failed: {exc}")
            return False

    def _find_backup_file(self, domain: str, relative_path: str) -> Path | None:
        """Locate a file within the backup by its domain-path hash."""
        if not self.backup_dir:
            return None
        file_hash = _domain_path_hash(domain, relative_path)
        # Backups may organize files in subdirs by first 2 chars of hash
        candidates = [
            self.backup_dir / file_hash,
            self.backup_dir / file_hash[:2] / file_hash,
        ]
        # Also search for UDID-named subdirectory
        for child in self.backup_dir.iterdir():
            if child.is_dir() and len(child.name) == 40:
                candidates.append(child / file_hash)
                candidates.append(child / file_hash[:2] / file_hash)

        for candidate in candidates:
            if candidate.exists():
                return candidate
        return None

    def strip_tcc_tracking_permissions(self) -> bool:
        """
        Modify the TCC.db in the backup to revoke tracking-related permissions.
        Revokes: kTCCServiceAddressBook, kTCCServicePhotos, kTCCServiceCamera,
        kTCCServiceMicrophone, kTCCServiceMotion, kTCCServiceMediaLibrary,
        and any app-tracking-transparency entries.
        """
        db_path = self._find_backup_file("HomeDomain", "Library/TCC/TCC.db")
        if not db_path:
            log.warning("TCC.db not found in backup.")
            return False

        try:
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()

            # Deny all app tracking transparency requests
            cursor.execute("""
                UPDATE access SET auth_value = 0
                WHERE service = 'kTCCServiceAppTrackingTransparency'
            """)
            att_revoked = cursor.rowcount

            # Also check for the alternative service name
            cursor.execute("""
                UPDATE access SET auth_value = 0
                WHERE service LIKE '%Tracking%'
            """)

            conn.commit()
            conn.close()

            log.info("TCC: Revoked %d tracking permissions.", att_revoked)
            self.modifications.append(f"TCC: Revoked {att_revoked} tracking permissions")
            return True
        except Exception as exc:
            log.error("Failed to modify TCC.db: %s", exc)
            return False

    def strip_safari_tracking(self) -> bool:
        """Modify Safari preferences in the backup to maximize privacy."""
        plist_path = self._find_backup_file("HomeDomain", "Library/Preferences/com.apple.mobilesafari.plist")
        if not plist_path:
            log.warning("Safari preferences not found in backup.")
            return False

        try:
            with open(plist_path, "rb") as f:
                prefs = plistlib.load(f)

            # Enable all privacy protections
            privacy_settings = {
                "SearchEngineStringSetting": "DuckDuckGo",
                "WebKitPreferences.privateClickMeasurementEnabled": False,
                "SafariSendDoNotTrackHTTPHeader": True,
                "BlockStoragePolicy": 2,  # Block all third-party cookies
                "WebKitStorageBlockingPolicy": 2,
                "PreferencesModernContentBlockersEnabled": True,
                "WBSPrivateBrowsingDNTHeaderEnabled": True,
                "WebKitPreferences.crossSiteTrackingPreventionEnabled": True,
                "FraudulentWebsiteWarning": True,
            }

            prefs.update(privacy_settings)

            with open(plist_path, "wb") as f:
                plistlib.dump(prefs, f)

            log.info("Safari tracking settings stripped and privacy hardened.")
            self.modifications.append("Safari: Privacy settings hardened (DoNotTrack, block cookies, ITP)")
            return True
        except Exception as exc:
            log.error("Failed to modify Safari preferences: %s", exc)
            return False

    def strip_diagnostics_sharing(self) -> bool:
        """Disable diagnostic data submission in the backup."""
        plist_path = self._find_backup_file(
            "HomeDomain", "Library/Preferences/com.apple.DiagnosticDataSubmission.plist"
        )

        # Even if the plist doesn't exist, we can try to find and modify Preferences.plist
        prefs_path = self._find_backup_file(
            "HomeDomain", "Library/Preferences/com.apple.Preferences.plist"
        )

        modified = False

        if plist_path:
            try:
                with open(plist_path, "rb") as f:
                    prefs = plistlib.load(f)
                prefs["AutoSubmit"] = False
                prefs["ThirdPartyDataSubmit"] = False
                prefs["DiagnosticDataShared"] = False
                with open(plist_path, "wb") as f:
                    plistlib.dump(prefs, f)
                modified = True
                log.info("Diagnostics sharing disabled.")
            except Exception as exc:
                log.error("Failed to modify diagnostics plist: %s", exc)

        if prefs_path:
            try:
                with open(prefs_path, "rb") as f:
                    prefs = plistlib.load(f)
                prefs["kDiagnosticsSubmissionEnabled"] = False
                prefs["kDiagnosticsAppSubmissionEnabled"] = False
                with open(prefs_path, "wb") as f:
                    plistlib.dump(prefs, f)
                modified = True
            except Exception:
                pass

        if modified:
            self.modifications.append("Diagnostics: Submission disabled")
        return modified

    def strip_ad_tracking(self) -> bool:
        """Disable advertising identifier and personalized ads in the backup."""
        modified = False

        for plist_name in ["com.apple.AdLib.plist", "com.apple.adsupport.plist"]:
            plist_path = self._find_backup_file("HomeDomain", f"Library/Preferences/{plist_name}")
            if plist_path:
                try:
                    with open(plist_path, "rb") as f:
                        prefs = plistlib.load(f)
                    prefs["allowApplePersonalizedAdvertising"] = False
                    prefs["forceLimitAdTracking"] = True
                    prefs["LimitAdTracking"] = True
                    prefs["personalizedAdsEnabled"] = False
                    with open(plist_path, "wb") as f:
                        plistlib.dump(prefs, f)
                    modified = True
                except Exception as exc:
                    log.error("Failed to modify %s: %s", plist_name, exc)

        if modified:
            self.modifications.append("Advertising: IDFA tracking disabled, personalized ads blocked")
            log.info("Ad tracking preferences stripped.")
        return modified

    def strip_location_tracking(self) -> bool:
        """Tighten location services settings in the backup."""
        plist_path = self._find_backup_file("HomeDomain", "Library/Preferences/com.apple.locationd.plist")
        if not plist_path:
            log.warning("locationd preferences not found in backup.")
            return False

        try:
            with open(plist_path, "rb") as f:
                prefs = plistlib.load(f)

            # Disable significant locations and other analytics
            prefs["SignificantLocationsEnabled"] = False
            prefs["LocationServicesRecentRequest"] = {}
            prefs["HistoricalLocationsEnabled"] = False
            prefs["SystemServicesShareMyLocation"] = False

            with open(plist_path, "wb") as f:
                plistlib.dump(prefs, f)

            self.modifications.append("Location: Significant Locations disabled, history cleared")
            log.info("Location tracking settings stripped.")
            return True
        except Exception as exc:
            log.error("Failed to modify locationd prefs: %s", exc)
            return False

    def strip_spotlight_siri(self) -> bool:
        """Disable Spotlight suggestions and Siri data collection in backup."""
        plist_path = self._find_backup_file("HomeDomain", "Library/Preferences/com.apple.Spotlight.plist")
        if not plist_path:
            return False

        try:
            with open(plist_path, "rb") as f:
                prefs = plistlib.load(f)

            prefs["SiriSuggestionsEnabled"] = False
            prefs["ShowSiriSuggestionsInLookup"] = False
            prefs["ShowSiriSuggestionsInSpotlight"] = False
            prefs["SiriCanLearnFromAppContent"] = False

            with open(plist_path, "wb") as f:
                plistlib.dump(prefs, f)

            self.modifications.append("Spotlight/Siri: Suggestions and learning disabled")
            return True
        except Exception:
            return False

    def delete_cookies(self) -> bool:
        """Remove the binary cookies file from the backup."""
        cookie_path = self._find_backup_file("HomeDomain", "Library/Cookies/Cookies.binarycookies")
        if cookie_path:
            try:
                os.remove(cookie_path)
                self.modifications.append("Cookies: Safari cookie store deleted")
                log.info("Cookie store removed from backup.")
                return True
            except Exception as exc:
                log.error("Failed to delete cookies: %s", exc)
        return False

    def run_full_strip(self, progress_callback=None) -> list[str]:
        """
        Execute all stripping operations on the current backup.
        Returns list of modifications made.
        """
        self.modifications.clear()
        steps = [
            ("Revoking tracking permissions (TCC)", self.strip_tcc_tracking_permissions),
            ("Hardening Safari privacy", self.strip_safari_tracking),
            ("Disabling diagnostics sharing", self.strip_diagnostics_sharing),
            ("Killing ad tracking / IDFA", self.strip_ad_tracking),
            ("Stripping location tracking", self.strip_location_tracking),
            ("Disabling Spotlight/Siri data collection", self.strip_spotlight_siri),
            ("Deleting cookie stores", self.delete_cookies),
        ]

        for desc, func in steps:
            if progress_callback:
                progress_callback(desc)
            try:
                func()
            except Exception as exc:
                log.error("Step failed (%s): %s", desc, exc)

        return self.modifications

    def cleanup(self):
        """Remove the temporary backup directory."""
        if self.backup_dir and self.backup_dir.exists():
            try:
                shutil.rmtree(self.backup_dir)
                log.info("Cleaned up backup directory.")
            except Exception as exc:
                log.error("Failed to clean up backup: %s", exc)
