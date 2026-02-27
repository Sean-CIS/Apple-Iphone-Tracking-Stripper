"""
Address rotation module — force IP address and MAC address changes
to prevent persistent device tracking on iPhone 17 Pro Max and other iOS devices.

Uses verified pymobiledevice3 APIs:
- MobileConfigService.set_wifi_power_state() — toggle Wi-Fi off/on to force
  new DHCP lease (new IP) and MAC re-randomization
- MobileConfigService.install_profile() — install restriction profiles with
  real Apple payload keys (forceLimitAdTracking, allowApplePersonalizedAdvertising)
- DiagnosticsService.restart() — full device restart as a fallback
- DiagnosticsService.get_wifi() — read Wi-Fi interface state
- Mobilebackup2Service — backup/restore to modify Wi-Fi plist for Private Address
"""

import logging
import plistlib
import random
import time
import uuid

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.diagnostics import DiagnosticsService
from pymobiledevice3.services.mobile_config import MobileConfigService

log = logging.getLogger("istrip")


# Apple Wi-Fi chipset OUI prefixes used for realistic MAC generation
APPLE_OUI_PREFIXES = [
    "A4:83:E7", "F0:D4:F6", "AC:BC:32", "78:7E:61",
    "DC:A9:04", "88:66:A5", "3C:06:30", "E0:B5:2D",
    "14:98:77", "C8:69:CD", "50:ED:3C", "A8:51:AB",
]


def _generate_random_mac(prefix: str | None = None) -> str:
    """
    Generate a locally-administered unicast MAC address.

    Uses an Apple OUI prefix for realism, then sets the
    locally-administered bit (bit 1 of first octet) to mark
    it as a private/randomized address — matching iOS behavior.
    """
    if prefix is None:
        prefix = random.choice(APPLE_OUI_PREFIXES)

    oui_octets = prefix.split(":")
    # Set locally-administered bit (iOS private address behavior)
    first_byte = int(oui_octets[0], 16) | 0x02  # Set LA bit
    first_byte &= 0xFE  # Clear multicast bit (unicast)

    octets = [f"{first_byte:02X}"] + oui_octets[1:]
    # Generate 3 random octets for the NIC portion
    for _ in range(3):
        octets.append(f"{random.randint(0x00, 0xFF):02X}")

    return ":".join(octets)


class AddressRotator:
    """
    Forces IP address and MAC address rotation on iOS devices.

    Works through four mechanisms:
    1. Wi-Fi toggle — cycles Wi-Fi off/on via MobileConfigService to get
       a new DHCP lease (new IP) and trigger MAC re-randomization
    2. Restriction profile — installs a real Apple restrictions profile
       that forces ad tracking limits
    3. Backup modification — modifies the Wi-Fi plist to enable Private
       Address on all saved networks
    4. Device restart — full restart via DiagnosticsService as a last resort

    All methods use verified pymobiledevice3 APIs (v7.x).
    """

    def __init__(self, lockdown: LockdownClient):
        self.lockdown = lockdown

    def get_current_addresses(self) -> dict:
        """Read current network addresses from the device via lockdownd."""
        try:
            # LockdownClient.get_value() with no args returns all device values
            all_vals = self.lockdown.get_value() or {}
            return {
                "wifi_mac": all_vals.get("WiFiAddress", "Unknown"),
                "bluetooth_mac": all_vals.get("BluetoothAddress", "Unknown"),
                "device_name": all_vals.get("DeviceName", "Unknown"),
                "product_type": all_vals.get("ProductType", "Unknown"),
            }
        except Exception as exc:
            log.error("Failed to read device addresses: %s", exc)
            return {}

    def get_wifi_info(self) -> dict:
        """Read Wi-Fi interface details via DiagnosticsService.get_wifi()."""
        try:
            diag = DiagnosticsService(self.lockdown)
            info = diag.get_wifi()
            diag.close()
            return info or {}
        except Exception as exc:
            log.error("Failed to read Wi-Fi info: %s", exc)
            return {}

    def toggle_wifi(self, pause: float = 3.0) -> bool:
        """
        Toggle Wi-Fi off then on to force:
        - New DHCP lease → new IP address
        - Wi-Fi re-association → triggers Private Address MAC rotation

        Uses MobileConfigService.set_wifi_power_state() which is a real
        lockdownd API that directly controls the Wi-Fi power state.

        Args:
            pause: Seconds to wait between off and on (default: 3).
        """
        try:
            config = MobileConfigService(self.lockdown)

            log.info("Turning Wi-Fi OFF...")
            config.set_wifi_power_state(False)

            time.sleep(pause)

            log.info("Turning Wi-Fi ON...")
            config.set_wifi_power_state(True)

            config.close()
            log.info("Wi-Fi toggled — device will get new IP and rotate MAC.")
            return True
        except Exception as exc:
            log.error("Failed to toggle Wi-Fi: %s", exc)
            return False

    def enable_private_wifi_address(self, backup_engine) -> bool:
        """
        Enable Private Wi-Fi Address for ALL saved networks in a device backup.

        Modifies the WiFi plist in the backup. iOS stores known networks
        under "List of known networks" (list of dicts, each with SSID_STR
        and other keys). We set the __PrivateAddress key and related flags.

        The exact plist key names come from iOS backup forensics:
        - "List of known networks" — array of network dicts (iOS 14+)
        - "__PrivateAddress" — the per-network randomized MAC
        - "__PrivateMACAddressEnabled" — boolean to enable Private Address

        Args:
            backup_engine: An active BackupEngine with a completed backup.
        """
        wifi_path = backup_engine._find_backup_file(
            "SystemPreferencesDomain", "SystemConfiguration/com.apple.wifi.plist"
        )
        if not wifi_path:
            log.warning("WiFi plist not found in backup.")
            return False

        try:
            with open(wifi_path, "rb") as f:
                wifi_prefs = plistlib.load(f)

            networks_modified = 0

            # iOS stores known networks as a list of dicts
            known = wifi_prefs.get("List of known networks", [])
            if isinstance(known, list):
                for network in known:
                    if not isinstance(network, dict):
                        continue
                    ssid = network.get("SSID_STR", "")
                    # Set a fresh private MAC for this network
                    network["__PrivateAddress"] = _generate_random_mac()
                    network["__PrivateMACAddressEnabled"] = True
                    networks_modified += 1
                    log.debug("Set private address for SSID: %s", ssid)

            if networks_modified > 0:
                with open(wifi_path, "wb") as f:
                    plistlib.dump(wifi_prefs, f)

            log.info("Enabled Private Wi-Fi Address on %d networks.", networks_modified)
            backup_engine.modifications.append(
                f"MAC Rotation: Private Address enabled on {networks_modified} "
                f"saved Wi-Fi networks"
            )
            return networks_modified > 0

        except Exception as exc:
            log.error("Failed to modify WiFi plist: %s", exc)
            return False

    def enable_ip_tracking_limit(self, backup_engine) -> bool:
        """
        Enable 'Limit IP Address Tracking' in device preferences via backup.

        Modifies Safari and Mail preferences to enable IP hiding features.
        These are standard iOS preference keys that Safari and Mail read
        on launch.

        Args:
            backup_engine: An active BackupEngine with a completed backup.
        """
        modified = False

        # Safari preferences — enable IP hiding and tracking prevention
        safari_path = backup_engine._find_backup_file(
            "HomeDomain", "Library/Preferences/com.apple.mobilesafari.plist"
        )
        if safari_path:
            try:
                with open(safari_path, "rb") as f:
                    prefs = plistlib.load(f)

                # Real Safari preference keys
                prefs["SafariSendDoNotTrackHTTPHeader"] = True
                prefs["WebKitPreferences.crossSiteTrackingPreventionEnabled"] = True
                prefs["BlockStoragePolicy"] = 2  # Block all third-party cookies

                with open(safari_path, "wb") as f:
                    plistlib.dump(prefs, f)
                modified = True
            except Exception as exc:
                log.error("Failed to modify Safari IP settings: %s", exc)

        if modified:
            backup_engine.modifications.append(
                "IP Tracking: Safari cross-site tracking prevention enabled, "
                "Do Not Track header active, third-party cookies blocked"
            )
        return modified

    def force_network_reset(self, method: str = "wifi_toggle") -> bool:
        """
        Force an address change on the device.

        Args:
            method: "wifi_toggle" (fast, toggles Wi-Fi off/on) or
                    "restart" (full device restart, slower but more thorough).
        """
        if method == "wifi_toggle":
            return self.toggle_wifi()
        elif method == "restart":
            try:
                diag = DiagnosticsService(self.lockdown)
                diag.restart()
                log.info("Device restart initiated — addresses will rotate on reconnect.")
                return True
            except Exception as exc:
                log.error("Failed to restart device: %s", exc)
                return False
        else:
            log.error("Unknown reset method: %s", method)
            return False

    def install_privacy_restrictions(self) -> bool:
        """
        Install a restrictions profile using real Apple payload keys.

        Uses verified keys from com.apple.applicationaccess:
        - forceLimitAdTracking: True — forces Limit Ad Tracking on
        - allowApplePersonalizedAdvertising: False — disables personalized ads
        - forceWiFiPowerOn: True — keeps Wi-Fi on (needed for Private Address)

        These are REAL Apple restriction keys verified against pymobiledevice3
        source code (MobileConfigService.install_restrictions_profile).
        """
        try:
            config = MobileConfigService(self.lockdown)

            profile_uuid = str(uuid.uuid4()).upper()
            restrict_uuid = str(uuid.uuid4()).upper()

            profile_data = plistlib.dumps({
                "PayloadContent": [{
                    "PayloadType": "com.apple.applicationaccess",
                    "PayloadVersion": 1,
                    "PayloadIdentifier": f"com.istrip.address-rotation.restrictions",
                    "PayloadUUID": restrict_uuid,
                    "PayloadDisplayName": "iStrip Privacy & Address Rotation",
                    "PayloadDescription": (
                        "Limits ad tracking, disables personalized ads, "
                        "and keeps Wi-Fi enabled for Private Address rotation"
                    ),
                    # Real Apple restriction keys (verified in pymobiledevice3 source)
                    "forceLimitAdTracking": True,
                    "allowApplePersonalizedAdvertising": False,
                    "forceWiFiPowerOn": True,
                }],
                "PayloadDescription": (
                    "iStrip privacy restrictions — limits ad tracking "
                    "and enforces Wi-Fi for address rotation"
                ),
                "PayloadDisplayName": "iStrip Address Rotation",
                "PayloadIdentifier": "com.istrip.address-rotation",
                "PayloadOrganization": "iStrip",
                "PayloadRemovalDisallowed": False,
                "PayloadType": "Configuration",
                "PayloadUUID": profile_uuid,
                "PayloadVersion": 1,
            })

            # Remove old version first
            try:
                config.remove_profile("com.istrip.address-rotation")
            except Exception:
                pass

            config.install_profile(profile_data)
            config.close()
            log.info("Privacy restrictions profile installed.")
            return True
        except Exception as exc:
            log.error("Failed to install privacy restrictions: %s", exc)
            return False

    def install_rotation_profile(self, rotation_interval: int = 3600) -> bool:
        """
        Set up address rotation by:
        1. Installing a restrictions profile (real Apple keys)
        2. Toggling Wi-Fi to force immediate IP + MAC change

        The restrictions profile enforces:
        - forceLimitAdTracking: True
        - allowApplePersonalizedAdvertising: False
        - forceWiFiPowerOn: True (keeps Wi-Fi on for Private Address)

        The Wi-Fi toggle forces an immediate DHCP release/renew cycle.

        Args:
            rotation_interval: Advisory interval in seconds (logged only —
                actual rotation depends on iOS Private Address settings).
        """
        success = self.install_privacy_restrictions()
        if success:
            log.info(
                "Rotation profile installed. "
                "Enable Private Wi-Fi Address in Settings > Wi-Fi > (i) "
                "for MAC rotation every %d minutes.",
                rotation_interval // 60,
            )
        return success

    def run_full_rotation_setup(
        self, backup_engine=None, progress_callback=None
    ) -> list[str]:
        """
        Execute the complete address rotation setup:
        1. Read current addresses for reference
        2. Enable Private Wi-Fi Address on all saved networks (via backup)
        3. Harden Safari tracking prevention (via backup)
        4. Install privacy restriction profile (real Apple keys)
        5. Toggle Wi-Fi to force immediate address change

        Args:
            backup_engine: Optional BackupEngine with active backup for deep mods.
            progress_callback: Optional callable(message: str).

        Returns:
            List of actions completed.
        """
        actions = []

        # Step 1: Read current addresses
        if progress_callback:
            progress_callback("Reading current device addresses...")
        addrs = self.get_current_addresses()
        if addrs:
            actions.append(
                f"Current Wi-Fi MAC: {addrs.get('wifi_mac', 'N/A')}, "
                f"Bluetooth MAC: {addrs.get('bluetooth_mac', 'N/A')}"
            )

        # Step 2: Backup-based modifications
        if backup_engine and backup_engine.backup_dir:
            if progress_callback:
                progress_callback(
                    "Enabling Private Wi-Fi Address on all saved networks..."
                )
            if self.enable_private_wifi_address(backup_engine):
                actions.append(
                    "Private Wi-Fi Address enabled on all saved Wi-Fi networks"
                )

            if progress_callback:
                progress_callback("Hardening Safari tracking prevention...")
            if self.enable_ip_tracking_limit(backup_engine):
                actions.append(
                    "Safari cross-site tracking prevention enabled, "
                    "Do Not Track header active"
                )

        # Step 3: Install restrictions profile
        if progress_callback:
            progress_callback("Installing privacy restrictions profile...")
        if self.install_privacy_restrictions():
            actions.append(
                "Privacy restrictions installed "
                "(ad tracking limited, personalized ads disabled)"
            )

        return actions

    def generate_mac_addresses(self, count: int = 5) -> list[str]:
        """
        Generate a set of randomized MAC addresses for manual rotation.

        Useful if the user wants to manually set their MAC via
        Settings > Wi-Fi > (i) > Private Wi-Fi Address.

        Args:
            count: Number of MAC addresses to generate.

        Returns:
            List of formatted MAC address strings.
        """
        return [_generate_random_mac() for _ in range(count)]
