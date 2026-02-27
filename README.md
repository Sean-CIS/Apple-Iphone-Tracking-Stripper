# iStrip — iPhone Tracking Stripper

Advanced tracking removal tool for iOS devices connected via USB on Windows 11.

## What It Does

iStrip connects to your iPhone over USB and strips tracking, analytics, telemetry, and surveillance mechanisms at multiple levels:

### Tracking Removal Operations

| Operation | What It Strips |
|-----------|----------------|
| **Crash & Diagnostic Logs** | Clears all crash reports and diagnostic data Apple collects |
| **Configuration Profile Audit** | Detects and removes MDM, surveillance, and tracking profiles |
| **DNS Tracker Blocking** | Installs a DNS-over-HTTPS profile that blocks 200+ tracker domains at the network level |
| **Privacy Lockdown Profile** | Installs a profile that disables diagnostics submission and restricts ad tracking |
| **App Tracker Scanning** | Scans every installed app's sandbox for tracking SDKs (Facebook, Google, Adjust, AppsFlyer, etc.) |
| **App Tracking Data Cleanup** | Deletes tracking caches, analytics databases, and attribution files from app sandboxes |
| **Safari Stripping** | Clears cookies, cache, localStorage, and injects anti-tracking protections via CDP |
| **Photo GPS Stripping** | Removes GPS/location EXIF metadata from all photos on device |
| **Deep Backup-Based Hardening** | Backs up device, modifies TCC permissions, Safari settings, ad tracking prefs, location tracking, diagnostics sharing, and Siri data collection, then restores |
| **Live Network Audit** | Captures real-time device traffic and identifies connections to known tracker domains |
| **Syslog Monitor** | Watches device logs for analytics, location pings, ad SDK activity, and telemetry |

### Tracker Domain Coverage

Blocks and detects 200+ domains across these categories:
- Apple Analytics & Telemetry (iCloud metrics, diagnostics, Siri analytics, etc.)
- Ad Networks (Google, Facebook, Amazon, Microsoft, Twitter, TikTok, Snapchat, LinkedIn)
- Mobile SDK Trackers (Adjust, AppsFlyer, Branch, Firebase, Mixpanel, Amplitude, Segment, etc.)
- Fingerprinting & Cross-Device Tracking
- Location Tracking Services
- Data Brokers
- Carrier/OEM Tracking

## Requirements

- **Windows 11** (or Windows 10)
- **Python 3.10+**
- **iTunes** or **Apple Mobile Device drivers** installed (for USB communication)
- **iPhone** connected via USB with the device unlocked

## Installation

```bash
# Clone the repo
git clone https://github.com/Sean-CIS/Apple-Iphone-Tracking-Stripper.git
cd Apple-Iphone-Tracking-Stripper

# Install dependencies
pip install -r requirements.txt

# Run
python run.py
```

Or install as a package:

```bash
pip install -e .
istrip
```

## Usage

### Interactive Mode (default)
```bash
python run.py
```

This opens an interactive menu where you can:
1. Run the **full tracking strip** (all operations)
2. **Scan only** (detect tracking without removing)
3. **Network audit** (capture live traffic, identify trackers)
4. **Syslog monitor** (watch device logs for tracking)
5. **Individual operations** (pick specific things to run)

### Automatic Mode
```bash
python run.py --auto
```
Runs all tracking removal operations with minimal prompts.

### Options
```
--auto       Run full strip automatically
--verbose    Enable debug output
--udid UDID  Target a specific device
--version    Show version
```

## How It Works

iStrip communicates with your iPhone using Apple's own lockdownd protocol over USB, via the `pymobiledevice3` library. This is the same protocol iTunes uses. No jailbreak is required.

### Services Used
- **AFC** (Apple File Conduit) — File access to photos/media for GPS stripping
- **MCInstall** — Configuration profile management
- **CrashReportCopyMobile** — Crash/diagnostic log access and deletion
- **InstallationProxy** — App listing and management
- **HouseArrest** — Per-app sandbox file access
- **MobileBackup2** — Full backup/restore with privacy modifications
- **WebInspector** — Safari cookie/cache clearing via Chrome DevTools Protocol
- **PcapD** — Live network packet capture
- **OsTrace** — Real-time system log monitoring
- **Diagnostics** — Device information queries

## Notes

- Your iPhone must be **unlocked** and you must tap **"Trust"** when prompted on the device
- The **backup-based operations** will restart your device after restore
- **Safari stripping via CDP** requires Web Inspector to be enabled: Settings → Safari → Advanced → Web Inspector
- The DNS blocking profile may need to be **accepted** in Settings → General → VPN & Device Management on the iPhone
- All operations are performed over USB — no network connection to Apple or third parties is needed

## License

MIT
