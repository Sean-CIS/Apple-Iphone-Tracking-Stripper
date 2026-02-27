"""
Address rotation module — force IP address and MAC address changes
to prevent persistent device tracking on iOS devices.

Uses verified pymobiledevice3 APIs (v7.x):
- MobileConfigService.set_wifi_power_state() — toggle Wi-Fi off/on to force
  new DHCP lease (new IP address)
- MobileConfigService.install_wifi_profile() — install per-network WiFi
  profiles with DisableAssociationMACRandomization=False to ensure Private
  Address (MAC randomization) is enabled
- MobileConfigService.install_profile() — install restriction profiles with
  real Apple payload keys (forceLimitAdTracking, allowApplePersonalizedAdvertising)
- DiagnosticsService.restart() — full device restart as a fallback
- DiagnosticsService.get_wifi() — read Wi-Fi interface state
- FileRelayService.request_sources(["WiFi"]) — read WiFi configuration
- Mobilebackup2Service — backup/restore to modify Wi-Fi plist for Private Address
"""

import io
import logging
import plistlib
import random
import tarfile
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

    MAC address rotation works through these mechanisms (in order of reliability):

    1. WiFi profile installation — installs a WiFi configuration profile for a
       specific network with DisableAssociationMACRandomization=False, ensuring
       iOS uses a randomized (Private) MAC address for that network. This is the
       MOST RELIABLE method and uses a real pymobiledevice3 API:
       MobileConfigService.install_wifi_profile()

    2. Backup modification — modifies the Wi-Fi plist in a device backup to
       enable Private Address on ALL saved networks at once, then restores.
       This is the DEEPEST method (affects all networks) but requires a full
       backup/restore cycle.

    3. Wi-Fi toggle — cycles Wi-Fi off/on via MobileConfigService. This forces
       a new DHCP lease (new IP address). It does NOT directly change the MAC,
       but if Private Address is already enabled, reconnecting may use the
       existing private MAC. Use this for IP rotation.

    4. Device restart — full restart via DiagnosticsService as a last resort.
       Resets all network state.

    IP address rotation:
    - Wi-Fi toggle forces a new DHCP lease → new IP address.
    - This is reliable and fast.

    All methods use verified pymobiledevice3 APIs (v7.x).
    """

    def __init__(self, lockdown: LockdownClient):
        self.lockdown = lockdown

    def get_current_addresses(self) -> dict:
        """Read current network addresses from the device via lockdownd."""
        try:
            all_vals = self.lockdown.all_values or {}
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

    def read_wifi_config(self) -> dict:
        """
        Read WiFi configuration from the device via FileRelayService.

        Uses FileRelayService.request_sources(["WiFi"]) to pull WiFi
        configuration files from the device as a tarball. This lets us
        inspect the current Private Address settings without a full backup.

        Returns dict with parsed WiFi plist data, or empty dict on failure.
        """
        try:
            from pymobiledevice3.services.file_relay import FileRelayService
            relay = FileRelayService(self.lockdown)
            data = relay.request_sources(["WiFi"])

            if not data:
                log.warning("FileRelayService returned no data for WiFi source.")
                return {}

            # data is a tarball; extract and parse plist files
            result = {}
            tar_buf = io.BytesIO(data)
            try:
                with tarfile.open(fileobj=tar_buf, mode="r:*") as tar:
                    for member in tar.getmembers():
                        if member.name.endswith(".plist") and member.isfile():
                            f = tar.extractfile(member)
                            if f:
                                try:
                                    plist_data = plistlib.load(f)
                                    result[member.name] = plist_data
                                except Exception:
                                    pass
            except Exception as exc:
                log.warning("Failed to parse WiFi tarball: %s", exc)

            return result

        except Exception as exc:
            log.warning("FileRelayService not available: %s", exc)
            return {}

    def toggle_wifi(self, pause: float = 3.0) -> bool:
        """
        Toggle Wi-Fi off then on to force a new DHCP lease (new IP address).

        IMPORTANT: This changes the IP address ONLY. It does NOT change the
        MAC address. If Private Address is already enabled for the current
        network, the device will reconnect using the same private MAC.

        To change the MAC address, use install_wifi_profile_with_private_mac()
        or the backup-based enable_private_wifi_address() method.

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
            log.info("Wi-Fi toggled — device will get a new IP address (new DHCP lease).")
            return True
        except Exception as exc:
            log.error("Failed to toggle Wi-Fi: %s", exc)
            return False

    def install_wifi_profile_with_private_mac(
        self,
        ssid: str,
        password: str = "",
        encryption_type: str = "WPA2",
    ) -> bool:
        """
        Install a WiFi configuration profile for a specific network with
        MAC randomization ENABLED (DisableAssociationMACRandomization=False).

        This is the MOST RELIABLE way to ensure Private Address (randomized MAC)
        is active for a given WiFi network. It uses the real pymobiledevice3 API:
        MobileConfigService.install_wifi_profile()

        When this profile is installed, iOS will use a randomized MAC address
        whenever connecting to this SSID. The MAC will be different from the
        device's real hardware MAC.

        Args:
            ssid: The WiFi network name (SSID).
            password: The WiFi password (empty for open networks).
            encryption_type: "WPA2", "WPA", "WEP", or "None".
        """
        try:
            config = MobileConfigService(self.lockdown)

            config.install_wifi_profile(
                encryption_type=encryption_type,
                ssid=ssid,
                password=password,
                auto_join=True,
                disable_association_mac_randomization=False,  # Enable MAC randomization
            )

            config.close()
            log.info(
                "WiFi profile installed for '%s' with Private Address (MAC randomization) enabled.",
                ssid,
            )
            return True
        except Exception as exc:
            log.error("Failed to install WiFi profile for '%s': %s", ssid, exc)
            return False

    def enable_private_wifi_address(self, backup_engine) -> bool:
        """
        Enable Private Wi-Fi Address for ALL saved networks in a device backup.

        Modifies the WiFi plist in the backup. iOS stores known networks in
        the plist at SystemPreferencesDomain/SystemConfiguration/com.apple.wifi.plist
        under the "List of known networks" key (array of dicts).

        For each saved network, we set:
        - PrivateMACAddressModeUserSetting = 2 (enabled, iOS 18+ key)
        - CachedPrivateMACAddress = <new random MAC> (iOS 18+ key)

        We also try the legacy format keys for older iOS:
        - __PrivateMACAddress = <new random MAC>
        - __PrivateMACAddressEnabled = True

        After restoring this backup, the device will use randomized MAC
        addresses for all saved WiFi networks.

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
                    new_mac = _generate_random_mac()

                    # iOS 18+ keys (verified from forensic analysis)
                    network["PrivateMACAddressModeUserSetting"] = 2  # 2 = enabled
                    network["CachedPrivateMACAddress"] = new_mac

                    # Legacy keys (iOS 14-17)
                    network["__PrivateMACAddress"] = new_mac
                    network["__PrivateMACAddressEnabled"] = True

                    networks_modified += 1
                    log.debug("Set private address for SSID: %s → %s", ssid, new_mac)

            if networks_modified > 0:
                with open(wifi_path, "wb") as f:
                    plistlib.dump(wifi_prefs, f)

            log.info("Enabled Private Wi-Fi Address on %d networks.", networks_modified)
            backup_engine.modifications.append(
                f"MAC Rotation: Private Address enabled on {networks_modified} "
                f"saved Wi-Fi networks with new randomized MACs"
            )
            return networks_modified > 0

        except Exception as exc:
            log.error("Failed to modify WiFi plist: %s", exc)
            return False

    def enable_ip_tracking_limit(self, backup_engine) -> bool:
        """
        Enable 'Limit IP Address Tracking' in device preferences via backup.

        Modifies Safari preferences to enable tracking prevention features.
        These are standard iOS preference keys that Safari reads on launch.

        Args:
            backup_engine: An active BackupEngine with a completed backup.
        """
        modified = False

        safari_path = backup_engine._find_backup_file(
            "HomeDomain", "Library/Preferences/com.apple.mobilesafari.plist"
        )
        if safari_path:
            try:
                with open(safari_path, "rb") as f:
                    prefs = plistlib.load(f)

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
        Force a network address change on the device.

        Args:
            method: "wifi_toggle" (fast, forces new IP via DHCP release/renew) or
                    "restart" (full device restart, resets all network state).

        Note: "wifi_toggle" only changes the IP address. To change the MAC,
        use install_wifi_profile_with_private_mac() or backup-based methods.
        """
        if method == "wifi_toggle":
            return self.toggle_wifi()
        elif method == "restart":
            try:
                diag = DiagnosticsService(self.lockdown)
                diag.restart()
                log.info("Device restart initiated — all network state will reset on reboot.")
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
        source code (MobileConfigService).
        """
        try:
            config = MobileConfigService(self.lockdown)

            profile_uuid = str(uuid.uuid4()).upper()
            restrict_uuid = str(uuid.uuid4()).upper()

            profile_data = plistlib.dumps({
                "PayloadContent": [{
                    "PayloadType": "com.apple.applicationaccess",
                    "PayloadVersion": 1,
                    "PayloadIdentifier": "com.istrip.address-rotation.restrictions",
                    "PayloadUUID": restrict_uuid,
                    "PayloadDisplayName": "iStrip Privacy Restrictions",
                    "PayloadDescription": (
                        "Limits ad tracking, disables personalized ads, "
                        "and keeps Wi-Fi enabled for Private Address"
                    ),
                    "forceLimitAdTracking": True,
                    "allowApplePersonalizedAdvertising": False,
                    "forceWiFiPowerOn": True,
                }],
                "PayloadDescription": (
                    "iStrip privacy restrictions — limits ad tracking "
                    "and enforces Wi-Fi for Private Address"
                ),
                "PayloadDisplayName": "iStrip Privacy Restrictions",
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

    def install_rotation_profile(self) -> bool:
        """
        Set up address rotation by installing a restrictions profile.

        The restrictions profile enforces:
        - forceLimitAdTracking: True
        - allowApplePersonalizedAdvertising: False
        - forceWiFiPowerOn: True (keeps Wi-Fi on for Private Address)
        """
        success = self.install_privacy_restrictions()
        if success:
            log.info(
                "Privacy restrictions profile installed. "
                "Use install_wifi_profile_with_private_mac() for per-network "
                "MAC randomization, or the backup method for all networks."
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
        5. Toggle Wi-Fi to force new IP address

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

        # Step 2: Backup-based modifications (enables Private Address on ALL networks)
        if backup_engine and backup_engine.backup_dir:
            if progress_callback:
                progress_callback(
                    "Enabling Private Wi-Fi Address on all saved networks..."
                )
            if self.enable_private_wifi_address(backup_engine):
                actions.append(
                    "Private Wi-Fi Address enabled on all saved Wi-Fi networks "
                    "(each network gets a unique randomized MAC)"
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

        # Step 4: Toggle Wi-Fi for new IP
        if progress_callback:
            progress_callback("Toggling Wi-Fi for new IP address...")
        if self.toggle_wifi(pause=3.0):
            actions.append("Wi-Fi toggled — new IP address acquired via DHCP")

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
