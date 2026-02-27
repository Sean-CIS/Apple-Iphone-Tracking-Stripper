"""
Media file metadata stripping — remove EXIF location data, device identifiers,
and other tracking metadata from photos/videos on the device.
"""

import logging
import os
import struct
import tempfile
from pathlib import Path

from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.afc import AfcService

log = logging.getLogger("istrip")

# EXIF tag IDs for GPS and device info
GPS_TAGS = {
    0x8825,  # GPSInfo IFD pointer
}
DEVICE_TAGS = {
    0x010F,  # Make
    0x0110,  # Model
    0x0131,  # Software
    0x013B,  # Artist
    0xA430,  # CameraOwnerName
    0xA431,  # BodySerialNumber
    0xA432,  # LensSpecification
    0xA433,  # LensMake
    0xA434,  # LensModel
    0xA435,  # LensSerialNumber
    0x9286,  # UserComment
    0x927C,  # MakerNote
}


class MediaCleaner:
    """
    Access photos/videos via AFC and strip tracking metadata (EXIF GPS,
    device identifiers, timestamps in metadata).
    """

    def __init__(self, lockdown: LockdownClient):
        self.lockdown = lockdown
        self.afc = AfcService(self.lockdown)

    def list_photos(self) -> list[str]:
        """List all photo files in the DCIM directory."""
        photos = []
        try:
            dcim_entries = self.afc.listdir("/DCIM")
            for folder in dcim_entries:
                if folder in (".", ".."):
                    continue
                try:
                    files = self.afc.listdir(f"/DCIM/{folder}")
                    for f in files:
                        if f in (".", ".."):
                            continue
                        lower = f.lower()
                        if lower.endswith((".jpg", ".jpeg", ".heic", ".heif", ".png", ".tiff", ".dng")):
                            photos.append(f"/DCIM/{folder}/{f}")
                except Exception:
                    pass
        except Exception as exc:
            log.error("Failed to list DCIM: %s", exc)
        return photos

    def list_videos(self) -> list[str]:
        """List all video files in the DCIM directory."""
        videos = []
        try:
            dcim_entries = self.afc.listdir("/DCIM")
            for folder in dcim_entries:
                if folder in (".", ".."):
                    continue
                try:
                    files = self.afc.listdir(f"/DCIM/{folder}")
                    for f in files:
                        if f in (".", ".."):
                            continue
                        lower = f.lower()
                        if lower.endswith((".mov", ".mp4", ".m4v")):
                            videos.append(f"/DCIM/{folder}/{f}")
                except Exception:
                    pass
        except Exception as exc:
            log.error("Failed to list videos: %s", exc)
        return videos

    def strip_exif_gps(self, device_path: str) -> bool:
        """
        Download a photo, strip GPS EXIF data, and re-upload it.
        Uses a lightweight EXIF parser to zero out GPS IFD entries
        without needing PIL/Pillow.
        """
        tmp_dir = tempfile.mkdtemp(prefix="istrip_exif_")
        filename = os.path.basename(device_path)
        local_path = os.path.join(tmp_dir, filename)

        try:
            # Download
            self.afc.pull(device_path, local_path)

            # Read and modify
            with open(local_path, "rb") as f:
                data = bytearray(f.read())

            modified = self._strip_gps_from_jpeg(data)
            if not modified:
                log.debug("No GPS data found in %s or unsupported format.", device_path)
                return False

            # Write modified file
            with open(local_path, "wb") as f:
                f.write(data)

            # Upload back
            self.afc.push(local_path, device_path)
            log.debug("Stripped GPS from %s", device_path)
            return True

        except Exception as exc:
            log.error("Failed to strip GPS from %s: %s", device_path, exc)
            return False
        finally:
            try:
                os.remove(local_path)
                os.rmdir(tmp_dir)
            except Exception:
                pass

    def _strip_gps_from_jpeg(self, data: bytearray) -> bool:
        """
        Zero out GPS IFD entries in JPEG EXIF data in-place.
        Returns True if modifications were made.
        """
        # Check JPEG SOI marker
        if data[:2] != b'\xff\xd8':
            return False

        # Find APP1 (EXIF) marker
        pos = 2
        while pos < len(data) - 4:
            if data[pos] != 0xFF:
                pos += 1
                continue
            marker = data[pos + 1]
            if marker == 0xE1:  # APP1
                length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                # Check for "Exif\0\0"
                if data[pos + 4:pos + 10] == b'Exif\x00\x00':
                    return self._zero_gps_in_tiff(data, pos + 10, pos + 2 + length)
                pos += 2 + length
            elif marker == 0xDA:  # Start of scan — stop searching
                break
            elif marker in (0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9):
                pos += 2
            else:
                if pos + 3 < len(data):
                    length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                    pos += 2 + length
                else:
                    break
        return False

    def _zero_gps_in_tiff(self, data: bytearray, tiff_start: int, tiff_end: int) -> bool:
        """Zero out GPS-related IFD entries within the TIFF structure."""
        if tiff_start + 8 > len(data):
            return False

        # Determine byte order
        bo = data[tiff_start:tiff_start + 2]
        if bo == b'MM':
            endian = ">"
        elif bo == b'II':
            endian = "<"
        else:
            return False

        modified = False

        def read_u16(off):
            return struct.unpack(f"{endian}H", data[off:off + 2])[0]

        def read_u32(off):
            return struct.unpack(f"{endian}I", data[off:off + 4])[0]

        # Walk IFD0
        ifd_offset = read_u32(tiff_start + 4)
        abs_ifd = tiff_start + ifd_offset

        if abs_ifd + 2 > tiff_end:
            return False

        entry_count = read_u16(abs_ifd)
        for i in range(entry_count):
            entry_off = abs_ifd + 2 + (i * 12)
            if entry_off + 12 > tiff_end:
                break
            tag = read_u16(entry_off)
            if tag == 0x8825:  # GPSInfo pointer
                # Zero out the value (GPS IFD offset)
                gps_ifd_offset = read_u32(entry_off + 8)
                gps_abs = tiff_start + gps_ifd_offset

                # Zero the GPS IFD entries
                if gps_abs + 2 <= tiff_end:
                    gps_count = read_u16(gps_abs)
                    end = gps_abs + 2 + (gps_count * 12)
                    if end <= tiff_end:
                        for j in range(gps_abs, min(end, tiff_end)):
                            data[j] = 0
                        modified = True

                # Also zero the pointer itself
                for j in range(entry_off + 8, min(entry_off + 12, tiff_end)):
                    data[j] = 0
                modified = True

        return modified

    def scan_for_gps_data(self, limit: int = 100) -> list[str]:
        """
        Scan photos to find which ones contain GPS EXIF data.
        Returns list of device paths with GPS data.
        """
        photos = self.list_photos()[:limit]
        with_gps = []

        for photo in photos:
            tmp_dir = tempfile.mkdtemp(prefix="istrip_scan_")
            local = os.path.join(tmp_dir, os.path.basename(photo))
            try:
                self.afc.pull(photo, local)
                with open(local, "rb") as f:
                    data = bytearray(f.read())
                if self._has_gps_data(data):
                    with_gps.append(photo)
            except Exception:
                pass
            finally:
                try:
                    os.remove(local)
                    os.rmdir(tmp_dir)
                except Exception:
                    pass

        return with_gps

    def _has_gps_data(self, data: bytearray) -> bool:
        """Check if JPEG data contains GPS EXIF information."""
        if data[:2] != b'\xff\xd8':
            return False
        pos = 2
        while pos < len(data) - 4:
            if data[pos] != 0xFF:
                pos += 1
                continue
            marker = data[pos + 1]
            if marker == 0xE1:
                length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                if data[pos + 4:pos + 10] == b'Exif\x00\x00':
                    segment = data[pos + 10:pos + 2 + length]
                    # Look for GPS tag 0x8825
                    return b'\x88\x25' in segment or b'\x25\x88' in segment
                pos += 2 + length
            elif marker == 0xDA:
                break
            else:
                if pos + 3 < len(data):
                    length = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                    pos += 2 + length
                else:
                    break
        return False

    def strip_all_photos(self, progress_callback=None) -> dict:
        """
        Strip GPS metadata from all photos on the device.

        Returns:
            Dict with 'stripped', 'skipped', 'errors' counts.
        """
        photos = self.list_photos()
        results = {"stripped": 0, "skipped": 0, "errors": 0, "total": len(photos)}

        for i, photo in enumerate(photos):
            try:
                if self.strip_exif_gps(photo):
                    results["stripped"] += 1
                else:
                    results["skipped"] += 1
            except Exception:
                results["errors"] += 1

            if progress_callback and (i + 1) % 5 == 0:
                progress_callback(i + 1, len(photos))

        return results
