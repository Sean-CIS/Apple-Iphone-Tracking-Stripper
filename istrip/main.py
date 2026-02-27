"""
iStrip — iPhone Tracking Stripper
Main CLI interface with interactive menu system.
"""

import argparse
import sys
import time

from istrip import __version__
from istrip.utils.console import (
    print_banner, status, header, prompt_confirm, prompt_choice,
    progress_bar, GREEN, RED, YELLOW, CYAN, MAGENTA, BOLD, DIM, RESET,
)
from istrip.utils.logger import setup_logger
from istrip.device import DeviceManager


def run_connect(dm: DeviceManager) -> bool:
    """Connect to the iPhone."""
    header("DEVICE CONNECTION")
    status("Searching for connected iPhone...", "action")
    devices = dm.discover()
    if not devices:
        status("No iPhone detected. Make sure:", "error")
        status("  1. iPhone is connected via USB cable", "warn")
        status("  2. iPhone is unlocked", "warn")
        status("  3. iTunes/Apple Mobile Device drivers are installed", "warn")
        status("  4. You tapped 'Trust' on the iPhone if prompted", "warn")
        return False

    status(f"Found {len(devices)} device(s).", "ok")
    for d in devices:
        status(f"  UDID: {d['udid']}  ({d['connection_type']})", "info")

    if not dm.connect():
        return False

    status("Device connected and paired!", "ok")
    print(f"\n{DIM}{dm.info.summary()}{RESET}\n")
    return True


def run_full_strip(dm: DeviceManager):
    """Run the full automated tracking removal suite."""
    header("FULL TRACKING STRIP")
    status("This will run ALL tracking removal operations:", "action")
    print(f"""
    {BOLD}1.{RESET} Clear crash reports & diagnostic logs
    {BOLD}2.{RESET} Audit & remove suspicious profiles
    {BOLD}3.{RESET} Install DNS tracker-blocking profile
    {BOLD}4.{RESET} Install privacy lockdown profile
    {BOLD}5.{RESET} Scan & clean app tracking data
    {BOLD}6.{RESET} Strip Safari cookies, cache & storage
    {BOLD}7.{RESET} Strip photo GPS metadata
    {BOLD}8.{RESET} Force IP & MAC address rotation
         (hourly rotation + Private Relay)
    {BOLD}9.{RESET} Deep backup-based privacy hardening
         (backup → modify settings → restore)
    """)

    if not prompt_confirm("Proceed with full tracking strip?"):
        status("Cancelled.", "warn")
        return

    lockdown = dm.get_lockdown()
    results = {}

    # Step 1: Crash reports
    status("Clearing crash reports & diagnostic logs...", "action")
    try:
        from istrip.modules.crash_logs import CrashLogStripper
        cl = CrashLogStripper(lockdown)
        count = cl.get_report_count()
        cl.clear_all()
        results["crash_logs"] = f"Cleared {count} reports"
        status(f"Cleared {count} crash/diagnostic reports.", "ok")
    except Exception as exc:
        results["crash_logs"] = f"Failed: {exc}"
        status(f"Crash log clearing failed: {exc}", "error")

    # Step 2: Profile audit
    status("Auditing installed profiles...", "action")
    try:
        from istrip.modules.profile_manager import ProfileManager
        pm = ProfileManager(lockdown)
        suspicious = pm.audit_suspicious_profiles()
        if suspicious:
            status(f"Found {len(suspicious)} suspicious profile(s):", "warn")
            for sp in suspicious:
                status(f"  {sp['name']} — {', '.join(sp['flags'])}", "warn")
                if prompt_confirm(f"  Remove '{sp['name']}'?"):
                    pm.remove_profile(sp["identifier"])
                    status(f"  Removed: {sp['name']}", "ok")
        else:
            status("No suspicious profiles found.", "ok")
        results["profiles_audit"] = f"Found {len(suspicious)} suspicious"
    except Exception as exc:
        results["profiles_audit"] = f"Failed: {exc}"
        status(f"Profile audit failed: {exc}", "error")

    # Step 3: DNS tracker blocking
    status("Installing DNS tracker-blocking profile...", "action")
    try:
        from istrip.modules.profile_manager import ProfileManager
        pm = ProfileManager(lockdown)
        if pm.install_tracker_blocker():
            status("DNS tracker-blocking profile installed (AdGuard DNS).", "ok")
            results["dns_blocker"] = "Installed"
        else:
            results["dns_blocker"] = "Failed"
            status("Failed to install DNS blocker.", "error")
    except Exception as exc:
        results["dns_blocker"] = f"Failed: {exc}"
        status(f"DNS blocker installation failed: {exc}", "error")

    # Step 4: Privacy lockdown profile
    status("Installing privacy lockdown profile...", "action")
    try:
        from istrip.modules.profile_manager import ProfileManager
        pm = ProfileManager(lockdown)
        if pm.install_privacy_lockdown():
            status("Privacy lockdown profile installed.", "ok")
            results["privacy_profile"] = "Installed"
        else:
            results["privacy_profile"] = "Failed"
    except Exception as exc:
        results["privacy_profile"] = f"Failed: {exc}"
        status(f"Privacy profile failed: {exc}", "error")

    # Step 5: App tracking scan & clean
    status("Scanning apps for tracking SDKs...", "action")
    try:
        from istrip.modules.app_scanner import AppScanner
        scanner = AppScanner(lockdown)
        scan_results = scanner.full_scan(
            progress_callback=lambda cur, tot, name: progress_bar(cur, tot, name)
        )
        if scan_results:
            status(f"Found trackers in {len(scan_results)} apps.", "warn")
            for bid, data in scan_results.items():
                tracker_names = [t["description"] for t in data["trackers"]]
                status(f"  {data['app_name']}: {', '.join(set(tracker_names))}", "warn")
            if prompt_confirm("Clean tracking data from these apps?"):
                for bid in scan_results:
                    scanner.clear_app_tracking_data(bid)
                status("App tracking data cleaned.", "ok")
        else:
            status("No tracking SDKs detected in app sandboxes.", "ok")
        results["app_scan"] = f"{len(scan_results)} apps with trackers"
    except Exception as exc:
        results["app_scan"] = f"Failed: {exc}"
        status(f"App scan failed: {exc}", "error")

    # Step 6: Safari stripping
    status("Stripping Safari tracking data...", "action")
    try:
        from istrip.modules.safari_stripper import SafariStripper
        ss = SafariStripper(lockdown)
        safari_results = ss.full_strip()
        cleared = [k for k, v in safari_results.items() if v]
        results["safari"] = f"Cleared: {', '.join(cleared) if cleared else 'none (enable Web Inspector for full access)'}"
        status(f"Safari: {results['safari']}", "ok" if cleared else "warn")
    except Exception as exc:
        results["safari"] = f"Failed: {exc}"
        status(f"Safari stripping failed: {exc}", "error")

    # Step 7: Photo GPS stripping
    status("Stripping GPS metadata from photos...", "action")
    try:
        from istrip.modules.media_cleaner import MediaCleaner
        mc = MediaCleaner(lockdown)
        photo_results = mc.strip_all_photos(
            progress_callback=lambda cur, tot: progress_bar(cur, tot, "photos")
        )
        results["photos"] = f"Stripped: {photo_results['stripped']}, Skipped: {photo_results['skipped']}, Errors: {photo_results['errors']}"
        status(f"Photos — {results['photos']}", "ok")
    except Exception as exc:
        results["photos"] = f"Failed: {exc}"
        status(f"Photo stripping failed: {exc}", "error")

    # Step 8: Address rotation
    status("Setting up IP & MAC address rotation...", "action")
    try:
        from istrip.modules.address_rotation import AddressRotator
        rotator = AddressRotator(lockdown)
        if rotator.install_rotation_profile(rotation_interval=3600):
            results["address_rotation"] = "Rotation profile installed (hourly MAC + IP limit)"
            status("Address rotation profile installed (MAC rotates every 60 min).", "ok")
        else:
            results["address_rotation"] = "Profile installation failed"
            status("Address rotation profile failed to install.", "error")
    except Exception as exc:
        results["address_rotation"] = f"Failed: {exc}"
        status(f"Address rotation setup failed: {exc}", "error")

    # Step 9: Backup-based deep strip
    status("Starting deep backup-based privacy hardening...", "action")
    status("This will: backup device → modify privacy settings → restore", "info")
    if prompt_confirm("This takes several minutes and the device will restart. Proceed?"):
        try:
            from istrip.modules.backup_engine import BackupEngine
            engine = BackupEngine(lockdown)

            status("Creating device backup...", "action")
            if engine.create_backup(progress_callback=lambda m: status(m, "info")):
                status("Backup complete. Applying privacy modifications...", "action")
                mods = engine.run_full_strip(progress_callback=lambda m: status(m, "action"))
                if mods:
                    status(f"Applied {len(mods)} modifications:", "ok")
                    for mod in mods:
                        status(f"  {mod}", "ok")

                    status("Restoring modified backup to device...", "action")
                    if engine.restore_backup(progress_callback=lambda m: status(m, "info")):
                        status("Backup restore complete. Device may restart.", "ok")
                        results["backup_strip"] = f"{len(mods)} modifications applied"
                    else:
                        results["backup_strip"] = "Restore failed"
                        status("Restore failed.", "error")
                else:
                    status("No modifiable files found in backup.", "warn")
                    results["backup_strip"] = "No targets found"

                engine.cleanup()
            else:
                results["backup_strip"] = "Backup failed"
        except Exception as exc:
            results["backup_strip"] = f"Failed: {exc}"
            status(f"Backup strip failed: {exc}", "error")
    else:
        results["backup_strip"] = "Skipped by user"
        status("Backup-based strip skipped.", "warn")

    # Summary
    header("STRIP COMPLETE — SUMMARY")
    for operation, result in results.items():
        icon = "ok" if "fail" not in result.lower() and "error" not in result.lower() else "error"
        status(f"{operation:.<30} {result}", icon)


def run_scan_only(dm: DeviceManager):
    """Scan device for tracking without removing anything."""
    header("TRACKING SCAN (READ-ONLY)")
    lockdown = dm.get_lockdown()

    # Crash logs
    status("Counting diagnostic/crash logs...", "action")
    try:
        from istrip.modules.crash_logs import CrashLogStripper
        cl = CrashLogStripper(lockdown)
        count = cl.get_report_count()
        status(f"Crash/diagnostic reports on device: {count}", "info")
    except Exception as exc:
        status(f"Crash log check failed: {exc}", "error")

    # Profiles
    status("Checking installed profiles...", "action")
    try:
        from istrip.modules.profile_manager import ProfileManager
        pm = ProfileManager(lockdown)
        profiles = pm.list_profiles()
        status(f"Installed profiles: {len(profiles)}", "info")
        for p in profiles:
            status(f"  {p['name']} ({p['identifier']})", "info")
        suspicious = pm.audit_suspicious_profiles()
        if suspicious:
            status(f"Suspicious profiles: {len(suspicious)}", "warn")
            for sp in suspicious:
                status(f"  {sp['name']} — {', '.join(sp['flags'])}", "warn")
    except Exception as exc:
        status(f"Profile check failed: {exc}", "error")

    # App scanning
    status("Scanning apps for tracking SDKs...", "action")
    try:
        from istrip.modules.app_scanner import AppScanner
        scanner = AppScanner(lockdown)
        scan_results = scanner.full_scan(
            progress_callback=lambda cur, tot, name: progress_bar(cur, tot, name)
        )
        if scan_results:
            summary = scanner.get_tracking_summary(scan_results)
            status(f"Trackers found in {len(scan_results)} apps:", "warn")
            for tracker, apps in summary.items():
                status(f"  {tracker}: {', '.join(apps[:5])}", "warn")
        else:
            status("No tracking SDKs detected.", "ok")
    except Exception as exc:
        status(f"App scan failed: {exc}", "error")

    # Photo GPS
    status("Scanning photos for GPS metadata (first 50)...", "action")
    try:
        from istrip.modules.media_cleaner import MediaCleaner
        mc = MediaCleaner(lockdown)
        gps_photos = mc.scan_for_gps_data(limit=50)
        if gps_photos:
            status(f"Photos with GPS data: {len(gps_photos)} (of 50 scanned)", "warn")
        else:
            status("No GPS data found in scanned photos.", "ok")
    except Exception as exc:
        status(f"Photo scan failed: {exc}", "error")


def run_network_audit(dm: DeviceManager):
    """Capture live traffic and identify tracker connections."""
    header("LIVE NETWORK AUDIT")
    lockdown = dm.get_lockdown()

    duration = 30
    status(f"Capturing device network traffic for {duration} seconds...", "action")
    status("Use your phone normally during this time to detect trackers.", "info")
    print()

    try:
        from istrip.modules.network_audit import NetworkAuditor
        auditor = NetworkAuditor(lockdown)
        result = auditor.capture_and_analyze(
            duration=duration,
            callback=lambda sec, tc: progress_bar(sec, duration, f"trackers: {tc}"),
        )
        print()
        if result["trackers_found"]:
            status(f"Detected {len(result['trackers_found'])} tracker connections:", "warn")
            for domain, category in result["trackers_found"].items():
                status(f"  {domain} [{category}]", "warn")
        else:
            status("No known tracker connections detected in captured traffic.", "ok")
        status(f"Total packets analyzed: {result['total_packets']}", "info")
        status(f"Unique domains seen: {len(result['domains_seen'])}", "info")
    except Exception as exc:
        status(f"Network audit failed: {exc}", "error")


def run_syslog_monitor(dm: DeviceManager):
    """Monitor device syslog for tracking activity."""
    header("SYSLOG TRACKING MONITOR")
    lockdown = dm.get_lockdown()

    duration = 30
    status(f"Monitoring device logs for {duration} seconds...", "action")
    status("Use your phone normally — we'll detect tracking activity in real-time.", "info")
    print()

    try:
        from istrip.modules.syslog_monitor import SyslogMonitor
        monitor = SyslogMonitor(lockdown)

        def on_finding(category, message, process):
            status(f"[{category.upper()}] {message[:120]}", "warn")

        findings = monitor.monitor(duration=duration, callback=on_finding)
        print()
        summary = monitor.get_summary()
        if summary:
            status("Tracking activity detected:", "warn")
            for cat, count in summary.items():
                status(f"  {cat}: {count} event(s)", "warn")
        else:
            status("No tracking activity detected in logs.", "ok")
    except Exception as exc:
        status(f"Syslog monitor failed: {exc}", "error")


def run_address_rotation(dm: DeviceManager):
    """Set up IP and MAC address rotation."""
    header("IP & MAC ADDRESS ROTATION")
    lockdown = dm.get_lockdown()

    from istrip.modules.address_rotation import AddressRotator
    rotator = AddressRotator(lockdown)

    addrs = rotator.get_current_addresses()
    if addrs:
        status(f"Current Wi-Fi MAC:     {addrs.get('wifi_mac', 'N/A')}", "info")
        status(f"Current Bluetooth MAC: {addrs.get('bluetooth_mac', 'N/A')}", "info")
        status(f"Device:                {addrs.get('product_type', 'N/A')}", "info")

    print()
    status("Address rotation prevents persistent tracking by changing", "info")
    status("your device's IP and MAC addresses on a schedule.", "info")
    print()

    choice = prompt_choice("Select rotation mode:", [
        "Quick setup — install rotation profile (MAC every hour + IP limit)",
        "Full setup — backup-based deep rotation on all saved Wi-Fi networks",
        "Generate random MACs — for manual configuration",
        "Force immediate rotation — restart device for new addresses",
    ])

    if choice == 0:
        status("Installing address rotation profile...", "action")
        if rotator.install_rotation_profile(rotation_interval=3600):
            status("Address rotation profile installed!", "ok")
            status("  Wi-Fi MAC will rotate every 60 minutes", "ok")
            status("  IP address tracking is limited via Private Relay", "ok")
            status("  Bluetooth address randomization enforced", "ok")
        else:
            status("Failed to install rotation profile.", "error")

    elif choice == 1:
        status("This performs a full device backup, enables address rotation", "info")
        status("on ALL saved Wi-Fi networks, enables Private Relay, and restores.", "info")
        status("Your device will restart after restore.", "warn")
        if prompt_confirm("Proceed with full rotation setup?"):
            try:
                from istrip.modules.backup_engine import BackupEngine
                engine = BackupEngine(lockdown)

                status("Creating device backup...", "action")
                if engine.create_backup(progress_callback=lambda m: status(m, "info")):
                    status("Backup complete. Applying rotation settings...", "action")
                    actions = rotator.run_full_rotation_setup(
                        backup_engine=engine,
                        progress_callback=lambda m: status(m, "action"),
                    )
                    for action in actions:
                        status(f"  {action}", "ok")

                    if prompt_confirm("Restore modified backup to device?"):
                        status("Restoring backup...", "action")
                        engine.restore_backup(
                            progress_callback=lambda m: status(m, "info")
                        )
                        status("Restore complete. Device may restart.", "ok")
                    engine.cleanup()
                else:
                    status("Backup failed.", "error")
            except Exception as exc:
                status(f"Full rotation setup failed: {exc}", "error")

    elif choice == 2:
        macs = rotator.generate_mac_addresses(count=5)
        status("Generated MAC addresses for manual rotation:", "ok")
        status("To use: Settings > Wi-Fi > tap (i) > Private Wi-Fi Address", "info")
        print()
        for i, mac in enumerate(macs, 1):
            print(f"     {BOLD}{i}.{RESET} {GREEN}{mac}{RESET}")
        print()

    elif choice == 3:
        status("This will restart your device to force immediate address rotation.", "warn")
        status("Make sure address rotation is enabled first (option 1 or 2).", "info")
        if prompt_confirm("Restart device now?"):
            if rotator.force_network_reset():
                status("Device restarting — new IP and MAC on reconnect.", "ok")
            else:
                status("Failed to restart device.", "error")


def run_individual_module(dm: DeviceManager):
    """Let the user pick individual operations to run."""
    header("INDIVIDUAL OPERATIONS")
    choice = prompt_choice("Select an operation:", [
        "Clear crash reports & diagnostic logs",
        "Audit & manage configuration profiles",
        "Install DNS tracker-blocking profile",
        "Install privacy lockdown profile",
        "Scan apps for tracking SDKs",
        "Clean app tracking data",
        "Strip Safari data (cookies, cache, storage)",
        "Strip photo GPS metadata",
        "IP & MAC address rotation",
        "Deep backup-based privacy hardening",
        "Back to main menu",
    ])

    lockdown = dm.get_lockdown()

    if choice == 0:
        from istrip.modules.crash_logs import CrashLogStripper
        cl = CrashLogStripper(lockdown)
        count = cl.get_report_count()
        status(f"Found {count} crash/diagnostic reports.", "info")
        if count > 0 and prompt_confirm("Clear all?"):
            cl.clear_all()
            status("Cleared.", "ok")

    elif choice == 1:
        from istrip.modules.profile_manager import ProfileManager
        pm = ProfileManager(lockdown)
        profiles = pm.list_profiles()
        status(f"Installed profiles ({len(profiles)}):", "info")
        for p in profiles:
            status(f"  {p['name']} ({p['identifier']})", "info")
        suspicious = pm.audit_suspicious_profiles()
        if suspicious:
            status(f"Suspicious profiles ({len(suspicious)}):", "warn")
            for sp in suspicious:
                status(f"  {sp['name']} — {', '.join(sp['flags'])}", "warn")
                if prompt_confirm(f"Remove '{sp['name']}'?"):
                    pm.remove_profile(sp["identifier"])

    elif choice == 2:
        from istrip.modules.profile_manager import ProfileManager
        pm = ProfileManager(lockdown)
        dns_choice = prompt_choice("Select DNS provider:", [
            "AdGuard DNS (recommended — blocks ads + trackers)",
            "Cloudflare Families (blocks malware + adult content)",
            "NextDNS (customizable tracker blocking)",
            "Quad9 (malware blocking, privacy-focused)",
        ])
        servers = [
            "https://dns.adguard-dns.com/dns-query",
            "https://family.cloudflare-dns.com/dns-query",
            "https://dns.nextdns.io",
            "https://dns.quad9.net/dns-query",
        ]
        if pm.install_tracker_blocker(dns_server=servers[dns_choice]):
            status("DNS tracker-blocking profile installed!", "ok")
        else:
            status("Installation failed.", "error")

    elif choice == 3:
        from istrip.modules.profile_manager import ProfileManager
        pm = ProfileManager(lockdown)
        if pm.install_privacy_lockdown():
            status("Privacy lockdown profile installed!", "ok")
        else:
            status("Installation failed.", "error")

    elif choice == 4:
        from istrip.modules.app_scanner import AppScanner
        scanner = AppScanner(lockdown)
        status("Scanning all installed apps...", "action")
        results = scanner.full_scan(
            progress_callback=lambda cur, tot, name: progress_bar(cur, tot, name)
        )
        if results:
            summary = scanner.get_tracking_summary(results)
            print()
            status(f"Trackers found in {len(results)} apps:", "warn")
            for tracker, apps in summary.items():
                status(f"  {tracker}:", "warn")
                for app in apps:
                    status(f"    - {app}", "info")
        else:
            status("No tracking SDKs detected.", "ok")

    elif choice == 5:
        from istrip.modules.app_scanner import AppScanner
        scanner = AppScanner(lockdown)
        status("Scanning apps...", "action")
        results = scanner.full_scan(
            progress_callback=lambda cur, tot, name: progress_bar(cur, tot, name)
        )
        if results:
            print()
            for bid, data in results.items():
                status(f"Cleaning: {data['app_name']}...", "action")
                clean_result = scanner.clear_app_tracking_data(bid)
                if clean_result["cleared"]:
                    for c in clean_result["cleared"]:
                        status(f"  Removed: {c}", "ok")
            status("Done cleaning app tracking data.", "ok")
        else:
            status("No tracking data to clean.", "ok")

    elif choice == 6:
        from istrip.modules.safari_stripper import SafariStripper
        ss = SafariStripper(lockdown)
        status("Stripping Safari data...", "action")
        results = ss.full_strip()
        for op, success in results.items():
            if isinstance(success, bool):
                status(f"  {op}: {'done' if success else 'failed (enable Web Inspector?)'}", "ok" if success else "warn")
            else:
                status(f"  {op}: processed", "ok")

    elif choice == 7:
        from istrip.modules.media_cleaner import MediaCleaner
        mc = MediaCleaner(lockdown)
        photos = mc.list_photos()
        status(f"Found {len(photos)} photos on device.", "info")
        if photos and prompt_confirm(f"Strip GPS metadata from all {len(photos)} photos?"):
            results = mc.strip_all_photos(
                progress_callback=lambda cur, tot: progress_bar(cur, tot, "photos")
            )
            print()
            status(f"Stripped: {results['stripped']}, Skipped: {results['skipped']}, Errors: {results['errors']}", "ok")

    elif choice == 8:
        from istrip.modules.address_rotation import AddressRotator
        rotator = AddressRotator(lockdown)

        addrs = rotator.get_current_addresses()
        if addrs:
            status(f"Current Wi-Fi MAC:     {addrs.get('wifi_mac', 'N/A')}", "info")
            status(f"Current Bluetooth MAC: {addrs.get('bluetooth_mac', 'N/A')}", "info")

        rot_choice = prompt_choice("Select address rotation action:", [
            "Install rotation profile (MAC rotates every hour, IP tracking limited)",
            "Full rotation setup via backup (deepest — modifies all saved networks)",
            "Generate random MAC addresses (for manual use)",
            "Force immediate rotation (restarts device)",
        ])

        if rot_choice == 0:
            interval = 3600
            status(f"Installing rotation profile (interval: {interval // 60} min)...", "action")
            if rotator.install_rotation_profile(rotation_interval=interval):
                status("Address rotation profile installed!", "ok")
                status("  Wi-Fi MAC will rotate every 60 minutes", "ok")
                status("  IP address tracking is now limited via Private Relay", "ok")
            else:
                status("Failed to install rotation profile.", "error")

        elif rot_choice == 1:
            status("This will backup your device, enable address rotation on all", "info")
            status("saved Wi-Fi networks, enable Private Relay, then restore.", "info")
            status("Your device will restart after the restore.", "warn")
            if prompt_confirm("Proceed with full rotation setup?"):
                from istrip.modules.backup_engine import BackupEngine
                engine = BackupEngine(lockdown)
                status("Creating backup...", "action")
                if engine.create_backup(progress_callback=lambda m: status(m, "info")):
                    status("Applying address rotation to all saved networks...", "action")
                    actions = rotator.run_full_rotation_setup(
                        backup_engine=engine,
                        progress_callback=lambda m: status(m, "action"),
                    )
                    # Also run the standard backup privacy strip
                    engine.run_full_strip(progress_callback=lambda m: status(m, "action"))
                    for action in actions:
                        status(f"  {action}", "ok")
                    for mod in engine.modifications:
                        status(f"  {mod}", "ok")
                    if prompt_confirm("Restore modified backup to device?"):
                        status("Restoring...", "action")
                        engine.restore_backup(progress_callback=lambda m: status(m, "info"))
                    engine.cleanup()

        elif rot_choice == 2:
            macs = rotator.generate_mac_addresses(count=5)
            status("Generated MAC addresses for manual rotation:", "ok")
            status("Go to Settings > Wi-Fi > (i) > Private Wi-Fi Address", "info")
            for i, mac in enumerate(macs, 1):
                status(f"  {i}. {mac}", "ok")

        elif rot_choice == 3:
            status("This will restart your device to force new addresses.", "warn")
            if prompt_confirm("Restart device now?"):
                if rotator.force_network_reset():
                    status("Device restarting — new IP and MAC on reconnect.", "ok")
                else:
                    status("Failed to restart device.", "error")

    elif choice == 9:
        from istrip.modules.backup_engine import BackupEngine
        engine = BackupEngine(lockdown)
        status("This will backup your device, modify privacy settings, and restore.", "info")
        status("Your device will restart after the restore.", "warn")
        if prompt_confirm("Proceed?"):
            status("Creating backup...", "action")
            if engine.create_backup(progress_callback=lambda m: status(m, "info")):
                status("Applying privacy modifications...", "action")
                mods = engine.run_full_strip(progress_callback=lambda m: status(m, "action"))
                for mod in mods:
                    status(f"  {mod}", "ok")
                if prompt_confirm("Restore modified backup to device?"):
                    status("Restoring...", "action")
                    engine.restore_backup(progress_callback=lambda m: status(m, "info"))
                engine.cleanup()


def main():
    parser = argparse.ArgumentParser(
        prog="istrip",
        description="iStrip — Advanced iPhone Tracking Stripper",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose/debug output")
    parser.add_argument("--version", action="version", version=f"iStrip v{__version__}")
    parser.add_argument(
        "--auto", action="store_true",
        help="Run the full tracking strip automatically (no interactive prompts)",
    )
    parser.add_argument("--udid", type=str, help="Target a specific device by UDID")
    args = parser.parse_args()

    log = setup_logger(verbose=args.verbose)
    print_banner()

    dm = DeviceManager()
    if not run_connect(dm):
        sys.exit(1)

    if args.auto:
        run_full_strip(dm)
        sys.exit(0)

    # Interactive menu loop
    while True:
        header("MAIN MENU")
        choice = prompt_choice("What would you like to do?", [
            f"{BOLD}Full Tracking Strip{RESET} — Run all operations automatically",
            f"{BOLD}Scan Only{RESET} — Detect tracking without removing anything",
            f"{BOLD}Network Audit{RESET} — Capture live traffic & identify trackers",
            f"{BOLD}Syslog Monitor{RESET} — Watch device logs for tracking activity",
            f"{BOLD}Address Rotation{RESET} — Force IP & MAC address changes (hourly)",
            f"{BOLD}Individual Operations{RESET} — Pick specific operations to run",
            f"{BOLD}Device Info{RESET} — Show connected device information",
            f"{RED}Exit{RESET}",
        ])

        if choice == 0:
            run_full_strip(dm)
        elif choice == 1:
            run_scan_only(dm)
        elif choice == 2:
            run_network_audit(dm)
        elif choice == 3:
            run_syslog_monitor(dm)
        elif choice == 4:
            run_address_rotation(dm)
        elif choice == 5:
            run_individual_module(dm)
        elif choice == 6:
            header("DEVICE INFO")
            print(f"\n{dm.info.summary()}\n")
        elif choice == 7:
            status("Goodbye.", "ok")
            dm.disconnect()
            break


if __name__ == "__main__":
    main()
