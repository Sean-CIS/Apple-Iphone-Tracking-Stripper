"""
Address rotation module — force IP address and MAC address changes
to prevent persistent device tracking on iPhone 17 Pro Max and other iOS devices.

Capabilities:
- Enable Private Wi-Fi Address (per-network MAC randomization)
- Enable Rotating Wi-Fi Address (periodic MAC changes, iOS 18+)
- Force immediate IP address change via network reconnection
- Schedule hourly IP/MAC rotation via configuration profile
- Enable Limit IP Address Tracking (iCloud Private Relay)
- Generate randomized MAC addresses for manual configuration
"""

import logging
import plistlib
import random
import uuid

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.diagnostics import DiagnosticsService

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

    Works through three mechanisms:
    1. Backup modification — enables Private/Rotating Address on all saved Wi-Fi networks
    2. Configuration profile — installs enforcement profile for MAC rotation + IP limiting
    3. Network reset — forces device restart to trigger immediate address changes
    """

    def __init__(self, lockdown: LockdownClient):
        self.lockdown = lockdown

    def get_current_addresses(self) -> dict:
        """Read current network addresses from the device."""
        try:
            all_vals = self.lockdown.all_values
            return {
                "wifi_mac": all_vals.get("WiFiAddress", "Unknown"),
                "bluetooth_mac": all_vals.get("BluetoothAddress", "Unknown"),
                "device_name": all_vals.get("DeviceName", "Unknown"),
                "product_type": all_vals.get("ProductType", "Unknown"),
            }
        except Exception as exc:
            log.error("Failed to read device addresses: %s", exc)
            return {}

    def enable_private_wifi_address(self, backup_engine) -> bool:
        """
        Enable Private Wi-Fi Address for ALL saved networks in a device backup.

        Modifies the WiFi plist so every saved network uses a randomized MAC
        instead of the hardware MAC. Also enables Rotating Private Address
        (iOS 18+) with a 1-hour rotation interval.

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

            # Known networks are stored under different keys depending on iOS version
            network_keys = [
                "List of known networks",
                "KnownNetworks",
                "wifi.knownnetworks",
            ]

            for key in network_keys:
                if key not in wifi_prefs:
                    continue
                val = wifi_prefs[key]

                if isinstance(val, list):
                    for network in val:
                        if isinstance(network, dict):
                            network["PrivateMACAddress"] = _generate_random_mac()
                            network["PrivateAddressEnabled"] = True
                            network["RotatingPrivateAddress"] = True
                            network["RotatingPrivateAddressInterval"] = 3600
                            networks_modified += 1
                elif isinstance(val, dict):
                    for ssid, network in val.items():
                        if isinstance(network, dict):
                            network["PrivateMACAddress"] = _generate_random_mac()
                            network["PrivateAddressEnabled"] = True
                            network["RotatingPrivateAddress"] = True
                            network["RotatingPrivateAddressInterval"] = 3600
                            networks_modified += 1

            with open(wifi_path, "wb") as f:
                plistlib.dump(wifi_prefs, f)

            log.info("Enabled Private Wi-Fi Address on %d networks.", networks_modified)
            backup_engine.modifications.append(
                f"MAC Rotation: Private Address enabled on {networks_modified} "
                f"networks (rotating every hour)"
            )
            return networks_modified > 0

        except Exception as exc:
            log.error("Failed to modify WiFi plist: %s", exc)
            return False

    def enable_ip_tracking_limit(self, backup_engine) -> bool:
        """
        Enable 'Limit IP Address Tracking' in device preferences via backup.

        Activates iCloud Private Relay for Safari and Mail, masking the
        device's real IP address from trackers and websites.

        Args:
            backup_engine: An active BackupEngine with a completed backup.
        """
        modified = False

        # General preferences — enable IP address limiting
        prefs_path = backup_engine._find_backup_file(
            "HomeDomain", "Library/Preferences/com.apple.Preferences.plist"
        )
        if prefs_path:
            try:
                with open(prefs_path, "rb") as f:
                    prefs = plistlib.load(f)

                prefs["LimitIPAddressTracking"] = True
                prefs["PrivateRelayEnabled"] = True

                with open(prefs_path, "wb") as f:
                    plistlib.dump(prefs, f)
                modified = True
            except Exception as exc:
                log.error("Failed to modify Preferences.plist for IP limit: %s", exc)

        # Safari preferences — hide IP address
        safari_path = backup_engine._find_backup_file(
            "HomeDomain", "Library/Preferences/com.apple.mobilesafari.plist"
        )
        if safari_path:
            try:
                with open(safari_path, "rb") as f:
                    prefs = plistlib.load(f)

                prefs["WBSPrivateRelayEnabled"] = True
                prefs["WBSHideIPAddress"] = True

                with open(safari_path, "wb") as f:
                    plistlib.dump(prefs, f)
                modified = True
            except Exception as exc:
                log.error("Failed to modify Safari IP settings: %s", exc)

        # Mail preferences — protect mail activity / hide IP
        mail_path = backup_engine._find_backup_file(
            "HomeDomain", "Library/Preferences/com.apple.mobilemail.plist"
        )
        if mail_path:
            try:
                with open(mail_path, "rb") as f:
                    prefs = plistlib.load(f)

                prefs["ProtectMailActivity"] = True
                prefs["HideIPAddress"] = True

                with open(mail_path, "wb") as f:
                    plistlib.dump(prefs, f)
                modified = True
            except Exception as exc:
                log.error("Failed to modify Mail IP settings: %s", exc)

        if modified:
            backup_engine.modifications.append(
                "IP Rotation: Limit IP Address Tracking enabled "
                "(Private Relay + Hide IP in Safari & Mail)"
            )
        return modified

    def force_network_reset(self) -> bool:
        """
        Force a device restart, which triggers:
        - New DHCP lease (new IP address)
        - Wi-Fi re-association (triggers Private Address if enabled)
        - Bluetooth re-pairing with new randomized address

        Uses DiagnosticsService to restart the device.
        """
        try:
            diag = DiagnosticsService(self.lockdown)
            diag.restart()
            log.info("Device restart initiated — addresses will rotate on reconnect.")
            return True
        except Exception as exc:
            log.error("Failed to initiate device restart: %s", exc)
            return False

    @staticmethod
    def generate_rotation_profile(
        rotation_interval: int = 3600,
        identifier: str = "com.istrip.address-rotation",
    ) -> bytes:
        """
        Generate a .mobileconfig profile that enforces:
        - Wi-Fi Private Address on all connections
        - Rotating Wi-Fi Address at the specified interval
        - Limit IP Address Tracking via Private Relay

        Args:
            rotation_interval: Seconds between MAC rotations (default: 3600 = 1 hour).
            identifier: Profile identifier string.

        Returns:
            Profile bytes ready for installation.
        """
        profile_uuid = str(uuid.uuid4()).upper()

        payloads = []

        # Restrictions payload — enforce address privacy features
        restrict_uuid = str(uuid.uuid4()).upper()
        payloads.append({
            "PayloadType": "com.apple.applicationaccess",
            "PayloadVersion": 1,
            "PayloadIdentifier": f"{identifier}.restrictions",
            "PayloadUUID": restrict_uuid,
            "PayloadDisplayName": "Address Rotation Enforcement",
            "PayloadDescription": (
                "Enforces MAC randomization, rotating addresses, "
                "and IP tracking limits on all network connections"
            ),
            "forceWiFiPrivateAddress": True,
            "forceWiFiRotatingAddress": True,
            "forceLimitIPAddressTracking": True,
        })

        # WiFi payload — enforce Private Address settings
        wifi_uuid = str(uuid.uuid4()).upper()
        payloads.append({
            "PayloadType": "com.apple.wifi.managed",
            "PayloadVersion": 1,
            "PayloadIdentifier": f"{identifier}.wifi",
            "PayloadUUID": wifi_uuid,
            "PayloadDisplayName": "Private Address Enforcement",
            "PayloadDescription": (
                f"Rotates Wi-Fi MAC address every {rotation_interval // 60} minutes"
            ),
            "EnablePrivateAddress": True,
            "RotatePrivateAddress": True,
            "PrivateAddressRotationInterval": rotation_interval,
            "DisableAssociationMACRandomization": False,
        })

        interval_min = rotation_interval // 60
        profile = {
            "PayloadContent": payloads,
            "PayloadDescription": (
                f"Address rotation — rotates Wi-Fi MAC every {interval_min} min, "
                f"limits IP tracking, enforces Private Relay"
            ),
            "PayloadDisplayName": "iStrip Address Rotation",
            "PayloadIdentifier": identifier,
            "PayloadOrganization": "iStrip",
            "PayloadRemovalDisallowed": False,
            "PayloadType": "Configuration",
            "PayloadUUID": profile_uuid,
            "PayloadVersion": 1,
        }

        return plistlib.dumps(profile)

    def install_rotation_profile(self, rotation_interval: int = 3600) -> bool:
        """
        Generate and install the address rotation configuration profile.

        Args:
            rotation_interval: Seconds between rotations (default: 3600 = 1 hour).
        """
        from istrip.modules.profile_manager import ProfileManager

        profile_data = self.generate_rotation_profile(
            rotation_interval=rotation_interval
        )
        pm = ProfileManager(self.lockdown)

        # Remove old version first if it exists
        try:
            pm.remove_profile("com.istrip.address-rotation")
        except Exception:
            pass

        if pm.install_profile_data(profile_data):
            log.info(
                "Address rotation profile installed (interval: %ds).",
                rotation_interval,
            )
            return True
        log.error("Failed to install address rotation profile.")
        return False

    def run_full_rotation_setup(
        self, backup_engine=None, progress_callback=None
    ) -> list[str]:
        """
        Execute the complete address rotation setup:
        1. Read current addresses for reference
        2. Enable Private Wi-Fi Address on all saved networks (via backup)
        3. Enable Limit IP Address Tracking / Private Relay (via backup)
        4. Install address rotation enforcement profile

        Args:
            backup_engine: Optional BackupEngine with active backup for deep mods.
            progress_callback: Optional callable(message: str).

        Returns:
            List of actions completed.
        """
        actions = []

        # Step 1: Show current addresses
        if progress_callback:
            progress_callback("Reading current device addresses...")
        addrs = self.get_current_addresses()
        if addrs:
            actions.append(
                f"Current Wi-Fi MAC: {addrs.get('wifi_mac', 'N/A')}, "
                f"Bluetooth MAC: {addrs.get('bluetooth_mac', 'N/A')}"
            )

        # Step 2: Backup-based modifications (if backup engine provided)
        if backup_engine and backup_engine.backup_dir:
            if progress_callback:
                progress_callback(
                    "Enabling Private Wi-Fi Address on all saved networks..."
                )
            if self.enable_private_wifi_address(backup_engine):
                actions.append(
                    "Private Wi-Fi Address enabled on all saved networks "
                    "(hourly rotation)"
                )

            if progress_callback:
                progress_callback("Enabling Limit IP Address Tracking...")
            if self.enable_ip_tracking_limit(backup_engine):
                actions.append(
                    "Limit IP Address Tracking enabled "
                    "(Private Relay + Hide IP)"
                )

        # Step 3: Install rotation profile
        if progress_callback:
            progress_callback("Installing address rotation profile...")
        if self.install_rotation_profile(rotation_interval=3600):
            actions.append(
                "Address rotation profile installed "
                "(MAC rotates every 60 min, IP tracking limited)"
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
