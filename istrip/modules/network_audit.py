"""Network traffic auditing — capture and analyze device traffic for trackers."""

import logging
import struct
import threading
import time
from collections import defaultdict
from io import BytesIO

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.pcapd import PcapdService

from istrip.data.tracker_domains import get_all_tracker_domains, get_domains_by_category

log = logging.getLogger("istrip")


class NetworkAuditor:
    """
    Captures live network traffic from the device and identifies
    connections to known tracker domains.
    """

    def __init__(self, lockdown: LockdownClient):
        self.lockdown = lockdown
        self.tracker_domains = set(get_all_tracker_domains())
        self.categories = get_domains_by_category()
        self.detected: dict[str, list[str]] = defaultdict(list)
        self._stop_event = threading.Event()

    def _classify_domain(self, domain: str) -> str | None:
        """Check if a domain matches any known tracker category."""
        domain = domain.lower().strip(".")
        for cat_name, domains in self.categories.items():
            for td in domains:
                if domain == td or domain.endswith(f".{td}"):
                    return cat_name
        return None

    def _extract_dns_names(self, packet_data: bytes) -> list[str]:
        """
        Attempt to extract DNS query names from raw packet bytes.
        This is a best-effort parser for UDP port 53 DNS queries.
        """
        names = []
        try:
            # Look for DNS queries — scan for standard DNS header patterns
            # Minimum IP+UDP+DNS header is ~40 bytes
            if len(packet_data) < 40:
                return names

            data = packet_data
            # Try to find UDP payload with dest port 53
            for offset in range(14, min(len(data) - 12, 60)):
                # Check for dest port 53 (0x0035) in potential UDP header
                if data[offset + 2:offset + 4] == b'\x00\x35':
                    dns_start = offset + 8  # Skip UDP header
                    if dns_start + 12 > len(data):
                        break
                    # Parse DNS question section
                    qd_count = struct.unpack("!H", data[dns_start + 4:dns_start + 6])[0]
                    if qd_count == 0 or qd_count > 20:
                        continue
                    pos = dns_start + 12
                    for _ in range(qd_count):
                        labels = []
                        while pos < len(data):
                            length = data[pos]
                            pos += 1
                            if length == 0:
                                break
                            if length > 63:
                                pos += 1
                                break
                            if pos + length > len(data):
                                break
                            labels.append(data[pos:pos + length].decode("ascii", errors="ignore"))
                            pos += length
                        if labels:
                            names.append(".".join(labels))
                        pos += 4  # Skip QTYPE + QCLASS
                    break
        except Exception:
            pass
        return names

    def _extract_tls_sni(self, packet_data: bytes) -> list[str]:
        """
        Extract Server Name Indication (SNI) from TLS ClientHello messages.
        This catches HTTPS connections even when DNS is encrypted.
        """
        names = []
        try:
            data = packet_data
            # Search for TLS ClientHello signature
            search = b'\x16\x03'  # TLS record header (handshake + version 3.x)
            idx = 0
            while idx < len(data) - 10:
                idx = data.find(search, idx)
                if idx == -1:
                    break
                # Verify handshake type = ClientHello (0x01)
                if idx + 5 < len(data) and data[idx + 5] == 0x01:
                    # Search for SNI extension (type 0x0000)
                    ch_start = idx + 5
                    # Scan for the SNI extension
                    pos = ch_start + 38  # Skip past fixed ClientHello fields
                    if pos >= len(data):
                        idx += 1
                        continue
                    # Skip session ID
                    if pos < len(data):
                        sid_len = data[pos]
                        pos += 1 + sid_len
                    # Skip cipher suites
                    if pos + 2 <= len(data):
                        cs_len = struct.unpack("!H", data[pos:pos + 2])[0]
                        pos += 2 + cs_len
                    # Skip compression methods
                    if pos < len(data):
                        cm_len = data[pos]
                        pos += 1 + cm_len
                    # Extensions
                    if pos + 2 <= len(data):
                        ext_len = struct.unpack("!H", data[pos:pos + 2])[0]
                        pos += 2
                        ext_end = pos + ext_len
                        while pos + 4 <= min(ext_end, len(data)):
                            ext_type = struct.unpack("!H", data[pos:pos + 2])[0]
                            ext_data_len = struct.unpack("!H", data[pos + 2:pos + 4])[0]
                            pos += 4
                            if ext_type == 0x0000:  # SNI extension
                                if pos + 5 <= len(data):
                                    name_len = struct.unpack("!H", data[pos + 3:pos + 5])[0]
                                    if pos + 5 + name_len <= len(data):
                                        sni = data[pos + 5:pos + 5 + name_len].decode("ascii", errors="ignore")
                                        if sni:
                                            names.append(sni)
                            pos += ext_data_len
                idx += 1
        except Exception:
            pass
        return names

    def capture_and_analyze(self, duration: int = 30, callback=None) -> dict:
        """
        Capture device traffic for `duration` seconds and identify tracker connections.

        Args:
            duration: Seconds to capture.
            callback: Optional callable(seconds_elapsed, tracker_count) for progress.

        Returns:
            Dict with 'trackers_found' (domain -> category), 'total_packets', etc.
        """
        self.detected.clear()
        self._stop_event.clear()
        total_packets = 0
        all_domains_seen = set()

        try:
            service = PcapdService(self.lockdown)
        except Exception as exc:
            log.error("Failed to start packet capture: %s", exc)
            return {"trackers_found": {}, "total_packets": 0, "domains_seen": []}

        start_time = time.time()

        def _capture():
            nonlocal total_packets
            try:
                for packet in service.watch():
                    if self._stop_event.is_set():
                        break
                    total_packets += 1
                    # Extract domains from DNS and TLS SNI
                    domains = self._extract_dns_names(packet) + self._extract_tls_sni(packet)
                    for domain in domains:
                        all_domains_seen.add(domain)
                        cat = self._classify_domain(domain)
                        if cat and domain not in self.detected:
                            self.detected[domain] = cat
                            log.info("Tracker detected: %s [%s]", domain, cat)
            except Exception:
                pass  # Stream ended

        thread = threading.Thread(target=_capture, daemon=True)
        thread.start()

        # Wait for duration, providing progress callbacks
        elapsed = 0
        while elapsed < duration and not self._stop_event.is_set():
            time.sleep(1)
            elapsed = int(time.time() - start_time)
            if callback:
                callback(elapsed, len(self.detected))

        self._stop_event.set()
        thread.join(timeout=3)

        return {
            "trackers_found": dict(self.detected),
            "total_packets": total_packets,
            "domains_seen": sorted(all_domains_seen),
            "duration": elapsed,
        }

    def stop(self):
        """Stop an ongoing capture."""
        self._stop_event.set()
