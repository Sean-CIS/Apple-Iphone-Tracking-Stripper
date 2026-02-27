"""
Safari and WebKit data stripping — clear cookies, cache, history, and tracking
data using the WebInspector CDP protocol and AFC file access.
"""

import json
import logging
import time

from pymobiledevice3.lockdown import LockdownClient

log = logging.getLogger("istrip")


class SafariStripper:
    """
    Strip tracking data from Safari using the WebInspector service
    and Chrome DevTools Protocol (CDP).

    Requirements:
    - "Web Inspector" must be enabled in Safari settings on the device
      (Settings > Safari > Advanced > Web Inspector)
    """

    def __init__(self, lockdown: LockdownClient):
        self.lockdown = lockdown

    def _get_webinspector(self):
        """Create a WebInspector service connection."""
        from pymobiledevice3.services.webinspector import WebinspectorService
        return WebinspectorService(self.lockdown)

    def clear_cookies(self) -> bool:
        """Clear all Safari cookies via CDP Network.clearBrowserCookies."""
        try:
            inspector = self._get_webinspector()
            inspector.connect()
            # Use CDP protocol to clear cookies
            inspector.send_cdp_command("Network.clearBrowserCookies")
            inspector.close()
            log.info("Safari cookies cleared via CDP.")
            return True
        except Exception as exc:
            log.warning("Failed to clear cookies via CDP (Web Inspector may not be enabled): %s", exc)
            return False

    def clear_cache(self) -> bool:
        """Clear Safari browser cache via CDP Network.clearBrowserCache."""
        try:
            inspector = self._get_webinspector()
            inspector.connect()
            inspector.send_cdp_command("Network.clearBrowserCache")
            inspector.close()
            log.info("Safari cache cleared via CDP.")
            return True
        except Exception as exc:
            log.warning("Failed to clear cache via CDP: %s", exc)
            return False

    def clear_local_storage(self, origins: list[str] | None = None) -> dict:
        """
        Clear localStorage/sessionStorage for specific origins or all known origins.
        Uses CDP Storage.clearDataForOrigin.
        """
        results = {}
        try:
            inspector = self._get_webinspector()
            inspector.connect()

            storage_types = "cookies,local_storage,session_storage,indexeddb,websql,cache_storage"

            if origins:
                for origin in origins:
                    try:
                        inspector.send_cdp_command(
                            "Storage.clearDataForOrigin",
                            {"origin": origin, "storageTypes": storage_types},
                        )
                        results[origin] = "cleared"
                        log.info("Cleared storage for origin: %s", origin)
                    except Exception as exc:
                        results[origin] = f"failed: {exc}"
            else:
                # Clear for a broad set of common tracker origins
                tracker_origins = [
                    "https://www.google.com",
                    "https://www.facebook.com",
                    "https://www.amazon.com",
                    "https://twitter.com",
                    "https://www.tiktok.com",
                    "https://www.instagram.com",
                    "https://www.linkedin.com",
                    "https://www.youtube.com",
                    "https://www.reddit.com",
                    "https://www.bing.com",
                    "https://www.yahoo.com",
                ]
                for origin in tracker_origins:
                    try:
                        inspector.send_cdp_command(
                            "Storage.clearDataForOrigin",
                            {"origin": origin, "storageTypes": storage_types},
                        )
                        results[origin] = "cleared"
                    except Exception:
                        results[origin] = "skipped"

            inspector.close()
        except Exception as exc:
            log.warning("Failed to clear storage via CDP: %s", exc)
            results["_error"] = str(exc)

        return results

    def inject_tracking_protection_js(self) -> bool:
        """
        Inject JavaScript into open Safari tabs that disables common
        tracking mechanisms (navigator.sendBeacon, tracking pixels, etc.).
        This is a one-shot defense for currently open pages.
        """
        protection_js = """
        (function() {
            // Block navigator.sendBeacon (analytics/tracking beacons)
            navigator.sendBeacon = function() { return false; };

            // Block tracking pixel creation
            var origImage = window.Image;
            window.Image = function() {
                var img = new origImage();
                var origSet = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src').set;
                Object.defineProperty(img, 'src', {
                    set: function(url) {
                        var dominated = ['facebook.com/tr', 'google-analytics.com', 'doubleclick.net',
                                        'analytics', 'tracking', 'pixel', 'beacon', 'telemetry'];
                        var dominated_match = dominated.some(function(d) { return url.indexOf(d) !== -1; });
                        if (!dominated_match) {
                            origSet.call(this, url);
                        }
                    },
                    get: function() { return ''; }
                });
                return img;
            };

            // Spoof Do Not Track
            Object.defineProperty(navigator, 'doNotTrack', { get: function() { return '1'; }});

            // Block fingerprinting APIs
            var canvas = HTMLCanvasElement.prototype;
            var origToDataURL = canvas.toDataURL;
            canvas.toDataURL = function(type) {
                // Return a blank canvas to prevent fingerprinting
                var c = document.createElement('canvas');
                c.width = this.width;
                c.height = this.height;
                return origToDataURL.call(c, type);
            };

            console.log('[iStrip] Tracking protection injected.');
        })();
        """
        try:
            inspector = self._get_webinspector()
            inspector.connect()
            # Execute in all open tabs
            tabs = inspector.get_open_pages()
            injected = 0
            for tab in tabs:
                try:
                    inspector.execute_js(tab, protection_js)
                    injected += 1
                except Exception:
                    pass
            inspector.close()
            log.info("Tracking protection JS injected into %d tabs.", injected)
            return injected > 0
        except Exception as exc:
            log.warning("Failed to inject JS (Web Inspector may not be enabled): %s", exc)
            return False

    def full_strip(self) -> dict:
        """Run all Safari stripping operations."""
        results = {
            "cookies": self.clear_cookies(),
            "cache": self.clear_cache(),
            "storage": self.clear_local_storage(),
            "js_protection": self.inject_tracking_protection_js(),
        }
        return results
