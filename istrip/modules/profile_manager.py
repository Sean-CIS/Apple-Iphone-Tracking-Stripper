"""Configuration profile management — install, remove, audit, and generate tracker-blocking profiles."""

import logging
import plistlib
import uuid
from pathlib import Path

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.mobile_config import MobileConfigService

from istrip.data.tracker_domains import get_all_tracker_domains, get_domains_by_category

log = logging.getLogger("istrip")

PROFILE_DIR = Path(__file__).parent.parent / "profiles"


class ProfileManager:
    """Manage iOS configuration profiles for tracking removal."""

    def __init__(self, lockdown: LockdownClient):
        self.lockdown = lockdown
        self.service = MobileConfigService(self.lockdown)

    def list_profiles(self) -> list[dict]:
        """List all installed configuration profiles on the device."""
        try:
            result = self.service.get_profile_list()
            profiles = []
            ordered = result.get("OrderedIdentifiers", [])
            manifests = result.get("ProfileManifest", {})
            metadata = result.get("ProfileMetadata", {})
            for ident in ordered:
                info = metadata.get(ident, {})
                profiles.append({
                    "identifier": ident,
                    "name": info.get("PayloadDisplayName", ident),
                    "description": info.get("PayloadDescription", ""),
                    "organization": info.get("PayloadOrganization", ""),
                    "uuid": info.get("PayloadUUID", ""),
                })
            return profiles
        except Exception as exc:
            log.error("Failed to list profiles: %s", exc)
            return []

    def remove_profile(self, identifier: str) -> bool:
        """Remove a configuration profile by its identifier."""
        try:
            self.service.remove_profile(identifier)
            log.info("Removed profile: %s", identifier)
            return True
        except Exception as exc:
            log.error("Failed to remove profile %s: %s", identifier, exc)
            return False

    def install_profile(self, profile_path: str) -> bool:
        """Install a .mobileconfig profile onto the device."""
        try:
            data = Path(profile_path).read_bytes()
            self.service.install_profile(data)
            log.info("Installed profile from %s", profile_path)
            return True
        except Exception as exc:
            log.error("Failed to install profile: %s", exc)
            return False

    def install_profile_data(self, profile_bytes: bytes) -> bool:
        """Install a profile from raw bytes."""
        try:
            self.service.install_profile(profile_bytes)
            return True
        except Exception as exc:
            log.error("Failed to install profile: %s", exc)
            return False

    def audit_suspicious_profiles(self) -> list[dict]:
        """
        Scan installed profiles for potentially suspicious ones:
        - MDM profiles (device management / corporate surveillance)
        - Unknown VPN profiles
        - Profiles from untrusted organizations
        - Root certificate profiles (potential MITM)
        """
        suspicious = []
        profiles = self.list_profiles()
        mdm_keywords = ["mdm", "management", "mobile device", "supervise", "airwatch",
                        "jamf", "intune", "mobileiron", "workspace one", "meraki",
                        "kandji", "mosyle", "addigy", "hexnode", "filewave"]
        vpn_keywords = ["vpn", "tunnel", "proxy"]
        cert_keywords = ["certificate", "root ca", "ssl", "tls"]

        for prof in profiles:
            flags = []
            name_lower = prof["name"].lower()
            desc_lower = prof["description"].lower()
            ident_lower = prof["identifier"].lower()
            combined = f"{name_lower} {desc_lower} {ident_lower}"

            for kw in mdm_keywords:
                if kw in combined:
                    flags.append(f"MDM/Management keyword: '{kw}'")
                    break
            for kw in vpn_keywords:
                if kw in combined:
                    flags.append(f"VPN/Proxy keyword: '{kw}'")
                    break
            for kw in cert_keywords:
                if kw in combined:
                    flags.append(f"Certificate keyword: '{kw}'")
                    break

            if flags:
                suspicious.append({**prof, "flags": flags})

        return suspicious

    @staticmethod
    def generate_dns_blocker_profile(
        dns_server: str = "https://dns.adguard-dns.com/dns-query",
        profile_name: str = "iStrip Tracker Blocker",
        identifier: str = "com.istrip.tracker-blocker",
        description: str = "DNS-over-HTTPS tracker blocking profile installed by iStrip",
    ) -> bytes:
        """
        Generate a .mobileconfig profile that configures DNS-over-HTTPS
        to route all DNS through a tracker-blocking resolver.
        """
        profile_uuid = str(uuid.uuid4()).upper()
        payload_uuid = str(uuid.uuid4()).upper()

        profile = {
            "PayloadContent": [
                {
                    "DNSSettings": {
                        "DNSProtocol": "HTTPS",
                        "ServerURL": dns_server,
                    },
                    "OnDemandRules": [
                        {
                            "Action": "EvaluateConnection",
                            "ActionParameters": [
                                {
                                    "DomainAction": "NeverConnect",
                                    "Domains": get_all_tracker_domains()[:50],
                                }
                            ],
                        },
                        {"Action": "Connect"},
                    ],
                    "PayloadDescription": description,
                    "PayloadDisplayName": "DNS Settings",
                    "PayloadIdentifier": f"{identifier}.dns",
                    "PayloadType": "com.apple.dnsSettings.managed",
                    "PayloadUUID": payload_uuid,
                    "PayloadVersion": 1,
                    "ProhibitDisablement": False,
                }
            ],
            "PayloadDescription": description,
            "PayloadDisplayName": profile_name,
            "PayloadIdentifier": identifier,
            "PayloadOrganization": "iStrip",
            "PayloadRemovalDisallowed": False,
            "PayloadType": "Configuration",
            "PayloadUUID": profile_uuid,
            "PayloadVersion": 1,
        }

        return plistlib.dumps(profile)

    @staticmethod
    def generate_privacy_lockdown_profile(
        identifier: str = "com.istrip.privacy-lockdown",
    ) -> bytes:
        """
        Generate a configuration profile that enforces privacy settings:
        - Disable diagnostics submission
        - Restrict ad tracking
        - Limit personalized ads
        """
        profile_uuid = str(uuid.uuid4()).upper()

        payloads = []

        # Restrictions payload — disable diagnostics & ad tracking
        restrict_uuid = str(uuid.uuid4()).upper()
        payloads.append({
            "PayloadType": "com.apple.applicationaccess",
            "PayloadVersion": 1,
            "PayloadIdentifier": f"{identifier}.restrictions",
            "PayloadUUID": restrict_uuid,
            "PayloadDisplayName": "Privacy Restrictions",
            "PayloadDescription": "Restrict tracking and analytics collection",
            "allowDiagnosticSubmission": False,
            "forcePersonalizedAds": False,
            "allowApplePersonalizedAdvertising": False,
        })

        profile = {
            "PayloadContent": payloads,
            "PayloadDescription": "Privacy lockdown profile — disables tracking, analytics, and personalized ads",
            "PayloadDisplayName": "iStrip Privacy Lockdown",
            "PayloadIdentifier": identifier,
            "PayloadOrganization": "iStrip",
            "PayloadRemovalDisallowed": False,
            "PayloadType": "Configuration",
            "PayloadUUID": profile_uuid,
            "PayloadVersion": 1,
        }

        return plistlib.dumps(profile)

    def install_tracker_blocker(self, dns_server: str = "https://dns.adguard-dns.com/dns-query") -> bool:
        """Generate and install the DNS tracker-blocking profile."""
        data = self.generate_dns_blocker_profile(dns_server=dns_server)
        return self.install_profile_data(data)

    def install_privacy_lockdown(self) -> bool:
        """Generate and install the privacy lockdown profile."""
        data = self.generate_privacy_lockdown_profile()
        return self.install_profile_data(data)
