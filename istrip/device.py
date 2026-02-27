"""Core device connection and management."""

import logging
from dataclasses import dataclass, field

from pymobiledevice3.lockdown import create_using_usbmux, LockdownClient
from pymobiledevice3.usbmux import list_devices
from pymobiledevice3.exceptions import (
    NoDeviceConnectedError,
    PairingError,
    ConnectionFailedError,
)

log = logging.getLogger("istrip")


@dataclass
class DeviceInfo:
    """Holds information about a connected iOS device."""
    name: str = ""
    udid: str = ""
    product_type: str = ""
    ios_version: str = ""
    build_version: str = ""
    serial: str = ""
    wifi_mac: str = ""
    bluetooth_mac: str = ""
    ecid: str = ""
    imei: str = ""
    phone_number: str = ""
    is_paired: bool = False
    is_developer_mode: bool = False
    raw_values: dict = field(default_factory=dict)

    def summary(self) -> str:
        lines = [
            f"Device Name:      {self.name}",
            f"Product Type:     {self.product_type}",
            f"iOS Version:      {self.ios_version} ({self.build_version})",
            f"UDID:             {self.udid}",
            f"Serial:           {self.serial}",
            f"Wi-Fi MAC:        {self.wifi_mac}",
            f"Bluetooth MAC:    {self.bluetooth_mac}",
            f"ECID:             {self.ecid}",
            f"Paired:           {'Yes' if self.is_paired else 'No'}",
        ]
        return "\n".join(lines)


class DeviceManager:
    """Manages the USB connection to an iOS device via lockdownd."""

    def __init__(self):
        self.lockdown: LockdownClient | None = None
        self.info: DeviceInfo | None = None

    def discover(self) -> list[dict]:
        """List all connected iOS devices via usbmuxd."""
        try:
            devices = list_devices()
            return [{"udid": d.serial, "connection_type": d.connection_type} for d in devices]
        except Exception as exc:
            log.error("Failed to discover devices: %s", exc)
            return []

    def connect(self, udid: str | None = None) -> bool:
        """
        Connect and pair with a device.
        If udid is None, connects to the first available device.
        """
        try:
            kwargs = {}
            if udid:
                kwargs["serial"] = udid
            self.lockdown = create_using_usbmux(**kwargs)
            self._populate_info()
            log.info("Connected to %s (%s)", self.info.name, self.info.udid)
            return True
        except NoDeviceConnectedError:
            log.error("No iPhone detected. Make sure it's connected via USB and unlocked.")
            return False
        except PairingError:
            log.error("Pairing failed. Unlock your iPhone and tap 'Trust' when prompted.")
            return False
        except ConnectionFailedError as exc:
            log.error("Connection failed: %s", exc)
            return False
        except Exception as exc:
            log.error("Unexpected connection error: %s", exc)
            return False

    def _populate_info(self):
        """Read device values from lockdownd and populate DeviceInfo."""
        if not self.lockdown:
            return
        try:
            all_vals = self.lockdown.get_value() or {}
        except Exception:
            all_vals = {}

        self.info = DeviceInfo(
            name=all_vals.get("DeviceName", "Unknown"),
            udid=all_vals.get("UniqueDeviceID", ""),
            product_type=all_vals.get("ProductType", ""),
            ios_version=all_vals.get("ProductVersion", ""),
            build_version=all_vals.get("BuildVersion", ""),
            serial=all_vals.get("SerialNumber", ""),
            wifi_mac=all_vals.get("WiFiAddress", ""),
            bluetooth_mac=all_vals.get("BluetoothAddress", ""),
            ecid=str(all_vals.get("UniqueChipID", "")),
            imei=all_vals.get("InternationalMobileEquipmentIdentity", ""),
            phone_number=all_vals.get("PhoneNumber", ""),
            is_paired=True,
            raw_values=all_vals,
        )

    def get_lockdown(self) -> LockdownClient:
        """Return the active lockdown client, raising if not connected."""
        if not self.lockdown:
            raise RuntimeError("Not connected to any device. Call connect() first.")
        return self.lockdown

    def disconnect(self):
        """Clean up the connection."""
        self.lockdown = None
        self.info = None
        log.info("Disconnected from device.")
