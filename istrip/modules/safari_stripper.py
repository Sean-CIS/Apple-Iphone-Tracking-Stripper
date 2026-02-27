"""
Safari and WebKit data stripping — clear cookies, cache, history, and tracking
data using the WebInspector service and Inspector Protocol.

Uses verified pymobiledevice3 APIs:
- WebinspectorService.connect() — connect to the device's WebInspector
- WebinspectorService.get_open_application_pages() — list open browser pages
- WebinspectorService.inspector_session(app, page) — create an InspectorSession
- InspectorSession.send_command(method, **kwargs) — send protocol commands
- InspectorSession.runtime_evaluate(expression) — execute JavaScript in a page
"""

import logging

from pymobiledevice3.lockdown import LockdownClient

log = logging.getLogger("istrip")


class SafariStripper:
    """
    Strip tracking data from Safari using the WebInspector service.

    Requirements:
    - "Web Inspector" must be enabled in Safari settings on the device
      (Settings > Safari > Advanced > Web Inspector)
    - At least one Safari tab must be open for JS injection
    """

    def __init__(self, lockdown: LockdownClient):
        self.lockdown = lockdown

    def _get_webinspector(self):
        """Create a WebInspector service connection."""
        from pymobiledevice3.services.webinspector import WebinspectorService
        return WebinspectorService(self.lockdown)

    def _get_session_for_first_page(self, inspector):
        """
        Get an InspectorSession for the first available open page.

        Returns (session, app_page) or (None, None) if no pages found.
        """
        try:
            app_pages = inspector.get_open_application_pages(timeout=5)
            if not app_pages:
                log.warning("No open Safari pages found.")
                return None, None
            app_page = app_pages[0]
            session = inspector.inspector_session(
                app_page.application, app_page.page
            )
            return session, app_page
        except Exception as exc:
            log.warning("Failed to get inspector session: %s", exc)
            return None, None

    def clear_cookies(self) -> bool:
        """Clear all Safari cookies via Network.clearBrowserCookies command."""
        try:
            inspector = self._get_webinspector()
            inspector.connect()

            session, app_page = self._get_session_for_first_page(inspector)
            if session is None:
                inspector.close()
                return False

            session.send_command("Network.clearBrowserCookies")
            inspector.close()
            log.info("Safari cookies cleared.")
            return True
        except Exception as exc:
            log.warning(
                "Failed to clear cookies (Web Inspector may not be enabled): %s",
                exc,
            )
            return False

    def clear_cache(self) -> bool:
        """Clear Safari browser cache via Network.clearBrowserCache command."""
        try:
            inspector = self._get_webinspector()
            inspector.connect()

            session, app_page = self._get_session_for_first_page(inspector)
            if session is None:
                inspector.close()
                return False

            session.send_command("Network.clearBrowserCache")
            inspector.close()
            log.info("Safari cache cleared.")
            return True
        except Exception as exc:
            log.warning("Failed to clear cache: %s", exc)
            return False

    def clear_local_storage(self, origins: list[str] | None = None) -> dict:
        """
        Clear localStorage/sessionStorage for specific or common tracker origins.
        Uses Runtime.evaluate to call localStorage.clear() on page contexts.
        """
        results = {}
        try:
            inspector = self._get_webinspector()
            inspector.connect()

            session, app_page = self._get_session_for_first_page(inspector)
            if session is None:
                inspector.close()
                results["_error"] = "No open pages found"
                return results

            # Use JavaScript to clear localStorage and sessionStorage
            clear_js = """
            (function() {
                try { localStorage.clear(); } catch(e) {}
                try { sessionStorage.clear(); } catch(e) {}
                return 'cleared';
            })();
            """
            session.runtime_evaluate(clear_js)
            results["current_page"] = "cleared"
            log.info("Cleared localStorage/sessionStorage for current page.")

            # Also clear via all available pages
            try:
                app_pages = inspector.get_open_application_pages(timeout=3)
                for ap in app_pages[1:]:  # Skip first (already cleared)
                    try:
                        s = inspector.inspector_session(
                            ap.application, ap.page
                        )
                        s.runtime_evaluate(clear_js)
                        url = getattr(ap.page, "web_url", "unknown")
                        results[url] = "cleared"
                    except Exception:
                        pass
            except Exception:
                pass

            inspector.close()
        except Exception as exc:
            log.warning("Failed to clear storage: %s", exc)
            results["_error"] = str(exc)

        return results

    def inject_tracking_protection_js(self) -> bool:
        """
        Inject JavaScript into open Safari tabs that disables common
        tracking mechanisms (navigator.sendBeacon, tracking pixels, etc.).
        This is a one-shot defense for currently open pages.

        Uses InspectorSession.runtime_evaluate() to execute JS in each tab.
        """
        protection_js = """
        (function() {
            // Block navigator.sendBeacon (analytics/tracking beacons)
            navigator.sendBeacon = function() { return false; };

            // Block tracking pixel creation
            var origImage = window.Image;
            window.Image = function() {
                var img = new origImage();
                var origSet = Object.getOwnPropertyDescriptor(
                    HTMLImageElement.prototype, 'src'
                ).set;
                Object.defineProperty(img, 'src', {
                    set: function(url) {
                        var blocked = [
                            'facebook.com/tr', 'google-analytics.com',
                            'doubleclick.net', 'analytics', 'tracking',
                            'pixel', 'beacon', 'telemetry'
                        ];
                        var match = blocked.some(function(d) {
                            return url.indexOf(d) !== -1;
                        });
                        if (!match) {
                            origSet.call(this, url);
                        }
                    },
                    get: function() { return ''; }
                });
                return img;
            };

            // Spoof Do Not Track
            Object.defineProperty(navigator, 'doNotTrack', {
                get: function() { return '1'; }
            });

            // Block canvas fingerprinting
            var canvas = HTMLCanvasElement.prototype;
            var origToDataURL = canvas.toDataURL;
            canvas.toDataURL = function(type) {
                var c = document.createElement('canvas');
                c.width = this.width;
                c.height = this.height;
                return origToDataURL.call(c, type);
            };

            return '[iStrip] Tracking protection injected.';
        })();
        """
        try:
            inspector = self._get_webinspector()
            inspector.connect()

            app_pages = inspector.get_open_application_pages(timeout=5)
            if not app_pages:
                log.warning("No open Safari pages found for JS injection.")
                inspector.close()
                return False

            injected = 0
            for ap in app_pages:
                try:
                    session = inspector.inspector_session(
                        ap.application, ap.page
                    )
                    session.runtime_evaluate(protection_js)
                    injected += 1
                except Exception:
                    pass

            inspector.close()
            log.info("Tracking protection JS injected into %d tabs.", injected)
            return injected > 0
        except Exception as exc:
            log.warning(
                "Failed to inject JS (Web Inspector may not be enabled): %s",
                exc,
            )
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
