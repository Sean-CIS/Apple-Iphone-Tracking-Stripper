"""Scan installed apps for known tracking SDKs and data collection."""

import logging
from collections import defaultdict

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.house_arrest import HouseArrestService

log = logging.getLogger("istrip")

# Known tracking SDK identifiers found in app bundle IDs, frameworks, or file names
TRACKING_SDK_MARKERS = {
    "com.facebook.sdk": "Facebook SDK (user profiling, event tracking)",
    "com.facebook.appevents": "Facebook App Events (behavioral tracking)",
    "FBSDKCoreKit": "Facebook Core SDK",
    "com.google.firebase": "Firebase (Google analytics/crash reporting)",
    "com.google.analytics": "Google Analytics",
    "GoogleAnalytics": "Google Analytics Framework",
    "com.adjust": "Adjust (attribution tracking)",
    "com.appsflyer": "AppsFlyer (attribution tracking)",
    "com.branch": "Branch.io (deep link attribution)",
    "com.amplitude": "Amplitude (behavioral analytics)",
    "com.mixpanel": "Mixpanel (event analytics)",
    "com.segment": "Segment (data pipeline / multi-tracker)",
    "com.braze": "Braze (engagement tracking)",
    "com.onesignal": "OneSignal (push + analytics)",
    "com.clevertap": "CleverTap (user profiling)",
    "Crashlytics": "Crashlytics (crash + usage reporting)",
    "com.flurry": "Flurry (Yahoo analytics)",
    "com.kochava": "Kochava (attribution tracking)",
    "com.singular": "Singular.net (attribution)",
    "com.moengage": "MoEngage (user engagement tracking)",
    "com.urbanairship": "Airship (push + analytics)",
    "com.newrelic": "New Relic (performance + usage monitoring)",
    "com.bugsnag": "Bugsnag (error + session tracking)",
    "com.sentry": "Sentry (error reporting)",
    "com.instabug": "Instabug (user session recording)",
    "com.appdynamics": "AppDynamics (user flow tracking)",
    "com.localytics": "Localytics (analytics + marketing)",
    "com.leanplum": "Leanplum (A/B testing + analytics)",
    "com.tealium": "Tealium (tag management + data collection)",
    "com.adobe.mobile": "Adobe Analytics Mobile",
    "com.comscore": "comScore (audience measurement)",
    "com.chartbeat": "Chartbeat (real-time analytics)",
    "com.heapanalytics": "Heap (auto-capture analytics)",
    "com.fullstory": "FullStory (session replay)",
    "com.hotjar": "Hotjar (session recording)",
    "com.mouseflow": "Mouseflow (session replay)",
    "ATTrackingManager": "App Tracking Transparency (requests IDFA)",
}


class AppScanner:
    """Scan installed applications for tracking SDKs and privacy concerns."""

    def __init__(self, lockdown: LockdownClient):
        self.lockdown = lockdown

    def list_installed_apps(self) -> list[dict]:
        """Get all installed apps with their metadata."""
        try:
            proxy = InstallationProxyService(self.lockdown)
            apps = proxy.get_apps("User")
            result = []
            for bundle_id, info in apps.items():
                result.append({
                    "bundle_id": bundle_id,
                    "name": info.get("CFBundleDisplayName", info.get("CFBundleName", bundle_id)),
                    "version": info.get("CFBundleShortVersionString", "?"),
                    "vendor": info.get("CFBundleIdentifier", "").split(".")[1] if "." in info.get("CFBundleIdentifier", "") else "",
                    "container": info.get("Container", ""),
                    "executable": info.get("CFBundleExecutable", ""),
                    "minimum_os": info.get("MinimumOSVersion", ""),
                    "has_app_transport_security": "NSAppTransportSecurity" in info.get("entitlements", {}),
                })
            return sorted(result, key=lambda x: x["name"])
        except Exception as exc:
            log.error("Failed to list apps: %s", exc)
            return []

    def scan_app_for_trackers(self, bundle_id: str) -> list[dict]:
        """
        Scan a single app's sandbox for tracking SDK markers.
        Uses HouseArrest to access the app's container.
        """
        findings = []
        try:
            service = HouseArrestService(self.lockdown, bundle_id=bundle_id)
            try:
                root_files = service.listdir("/Documents") + service.listdir("/Library")
            except Exception:
                root_files = []

            for fname in root_files:
                fname_lower = fname.lower()
                for marker, description in TRACKING_SDK_MARKERS.items():
                    if marker.lower() in fname_lower:
                        findings.append({
                            "marker": marker,
                            "description": description,
                            "location": fname,
                        })

            # Check preferences plists
            try:
                prefs = service.listdir("/Library/Preferences")
                for pref in prefs:
                    pref_lower = pref.lower()
                    for marker, description in TRACKING_SDK_MARKERS.items():
                        if marker.lower() in pref_lower:
                            findings.append({
                                "marker": marker,
                                "description": description,
                                "location": f"Preferences/{pref}",
                            })
            except Exception:
                pass

            # Check for Caches with tracking names
            try:
                caches = service.listdir("/Library/Caches")
                for cache in caches:
                    cache_lower = cache.lower()
                    for marker, description in TRACKING_SDK_MARKERS.items():
                        if marker.lower() in cache_lower:
                            findings.append({
                                "marker": marker,
                                "description": description,
                                "location": f"Caches/{cache}",
                            })
            except Exception:
                pass

        except Exception as exc:
            log.debug("Cannot access sandbox for %s: %s", bundle_id, exc)

        return findings

    def full_scan(self, progress_callback=None) -> dict:
        """
        Scan all installed user apps for tracking SDKs.

        Returns:
            Dict mapping bundle_id -> list of tracker findings.
        """
        apps = self.list_installed_apps()
        results = {}
        total = len(apps)

        for i, app in enumerate(apps):
            bid = app["bundle_id"]
            findings = self.scan_app_for_trackers(bid)
            if findings:
                results[bid] = {
                    "app_name": app["name"],
                    "trackers": findings,
                }
            if progress_callback:
                progress_callback(i + 1, total, app["name"])

        return results

    def get_tracking_summary(self, scan_results: dict) -> dict:
        """Summarize scan results by tracker type."""
        summary = defaultdict(list)
        for bid, data in scan_results.items():
            for tracker in data["trackers"]:
                summary[tracker["description"]].append(data["app_name"])
        return dict(summary)

    def clear_app_tracking_data(self, bundle_id: str) -> dict:
        """
        Attempt to clear tracking-related data from an app's sandbox.
        Targets: Caches, tracking plists, analytics databases.
        """
        cleared = []
        errors = []
        try:
            service = HouseArrestService(self.lockdown, bundle_id=bundle_id)

            # Clear caches
            try:
                caches = service.listdir("/Library/Caches")
                for cache in caches:
                    cache_lower = cache.lower()
                    tracking_keywords = ["analytics", "track", "facebook", "firebase",
                                        "adjust", "appsflyer", "amplitude", "mixpanel",
                                        "segment", "braze", "flurry", "crash"]
                    for kw in tracking_keywords:
                        if kw in cache_lower:
                            try:
                                service.rm(f"/Library/Caches/{cache}")
                                cleared.append(f"Caches/{cache}")
                            except Exception:
                                # Might be a directory
                                try:
                                    self._rm_recursive(service, f"/Library/Caches/{cache}")
                                    cleared.append(f"Caches/{cache}")
                                except Exception as e:
                                    errors.append(f"Caches/{cache}: {e}")
                            break
            except Exception:
                pass

            # Clear tracking preference files
            try:
                prefs = service.listdir("/Library/Preferences")
                for pref in prefs:
                    pref_lower = pref.lower()
                    for marker in TRACKING_SDK_MARKERS:
                        if marker.lower() in pref_lower:
                            try:
                                service.rm(f"/Library/Preferences/{pref}")
                                cleared.append(f"Preferences/{pref}")
                            except Exception as e:
                                errors.append(f"Preferences/{pref}: {e}")
                            break
            except Exception:
                pass

        except Exception as exc:
            errors.append(f"Cannot access app: {exc}")

        return {"cleared": cleared, "errors": errors}

    def _rm_recursive(self, service, path: str):
        """Recursively remove a directory in an AFC-like service."""
        try:
            entries = service.listdir(path)
            for entry in entries:
                if entry in (".", ".."):
                    continue
                child = f"{path}/{entry}"
                try:
                    service.rm(child)
                except Exception:
                    self._rm_recursive(service, child)
            service.rm(path)
        except Exception:
            service.rm(path)
