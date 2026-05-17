"""
Module for forensic acquisition.
"""

import json
import exifread
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from .device import AndroidDevice
from .logger import ForensicLogger
from .hasher import ForensicHasher
from .parser import CallLogParser, SMSParser, BrowserParser

# Initialize logger for this module
logger = ForensicLogger()


class DataExtractor:
    """
    Handles data extraction from Android devices for forensic acquisition.
    Uses adb-shell for command execution and file transfer.
    """

    def __init__(self, device: AndroidDevice, output_dir: Path):
        """
        Args:
            device (AndroidDevice): The connected Android device instance.
            output_dir (Path): Base directory for saving extracted data.
        """
        self.device = device
        self.output_dir = output_dir
        self.call_log_permission_denied = False

    def get_installed_apps(self) -> List[Dict[str, Any]]:
        """
        Retrieves a list of all installed applications with their versions and install dates.

        Returns:
            List[Dict[str, Any]]: List of application metadata dictionaries.
        """
        try:
            logger.log_info("Enumerating installed packages...")
            raw_packages = self.device.adb.shell(
                "pm list packages"
            ).strip().splitlines()
            packages = [p.replace("package:", "").strip()
                        for p in raw_packages if p.startswith("package:")]

            app_list = []
            for pkg in packages:
                app_info = self._get_package_details(pkg)
                app_list.append(app_info)

            logger.log_info(
                f"Successfully retrieved info for {len(app_list)} packages."
            )
            return app_list
        except Exception as e:
            logger.log_error(f"Failed to list installed packages: {e}")
            return []

    def _get_package_details(self, package_name: str) -> Dict[str, Any]:
        """
        Parses dumpsys output to extract version and install date for a specific package.
        """
        details = {
            "package_name": package_name,
            "version": "Unknown",
            "install_date": "Unknown"
        }

        try:
            dump = self.device.adb.shell(f"dumpsys package {package_name}")

            # Extract version
            version_match = re.search(r"versionName=(.*)", dump)
            if version_match:
                details["version"] = version_match.group(1).strip()

            # Extract first install time
            install_match = re.search(r"firstInstallTime=(.*)", dump)
            if install_match:
                details["install_date"] = install_match.group(1).strip()

        except Exception as e:
            logger.log_warning(
                f"Could not get details for {package_name}: {e}")

        return details

    def extract_apps_to_json(
            self,
            filename: str = "installed_apps.json") -> Path:
        """
        Extracts application list and saves it as a JSON file in the output directory.
        """
        if isinstance(filename, Path):
            output_path = filename
        else:
            output_path = self.output_dir / filename

        apps = self.get_installed_apps()

        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(apps, f, indent=4)

            logger.log_info(f"Installed apps saved to: {output_path}")
            return output_path
        except Exception as e:
            logger.log_error(f"Failed to save installed apps to JSON: {e}")
            return output_path

    def extract_deleted_records_stats(self) -> Path:
        """Analyzes SQLite databases for deleted records via freelist count."""
        stats = {}
        out_path = self.output_dir / "deleted_record_analysis.json"

        call_db = self.output_dir / "call_log" / "calllog.db"
        count_calls = 0
        if call_db.exists() and call_db.stat().st_size > 0:
            parser = CallLogParser(call_db)
            count_calls = parser.get_freelist_count()
        logger.log_info(f"SQLite freelist_count for calllog.db: {count_calls}")
        stats["calls"] = {"freelist_count": count_calls, "recovery_possible": count_calls > 0}

        sms_db = self.output_dir / "sms" / "mmssms.db"
        count_sms = 0
        if sms_db.exists() and sms_db.stat().st_size > 0:
            parser = SMSParser(sms_db)
            count_sms = parser.get_freelist_count()
        logger.log_info(f"SQLite freelist_count for mmssms.db: {count_sms}")
        stats["sms"] = {"freelist_count": count_sms, "recovery_possible": count_sms > 0}

        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(stats, f, indent=4)
        except Exception as e:
            logger.log_error(f"Failed to save deleted records stats: {e}")
        return out_path

    def _convert_to_degrees(self, value):
        try:
            d = float(value.values[0].num) / float(value.values[0].den)
            m = float(value.values[1].num) / float(value.values[1].den)
            s = float(value.values[2].num) / float(value.values[2].den)
            return d + (m / 60.0) + (s / 3600.0)
        except Exception:
            return 0.0

    def extract_exif_gps(self) -> Path:
        """Extracts EXIF metadata from pulled images."""
        results = []
        out_path = self.output_dir / "media_metadata" / "exif_locations.json"
        manifest_path = self.output_dir / "media_metadata" / "storage_manifest.json"

        if not manifest_path.exists():
            return out_path

        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                files = json.load(f)
        except Exception:
            return out_path

        img_exts = {".jpg", ".jpeg", ".png"}
        images = [f for f in files if Path(f["filename"]).suffix.lower() in img_exts]

        for img in images:
            try:
                logger.log_info(f"EXIF image scanned: {img['filename']}")
                local_tmp = self.output_dir / "media_metadata" / f"tmp_{img['filename']}"
                self.device.adb.pull(img["path"], str(local_tmp))

                with open(local_tmp, "rb") as f:
                    tags = exifread.process_file(f, details=False)

                if "GPS GPSLatitude" in tags and "GPS GPSLongitude" in tags:
                    lat = self._convert_to_degrees(tags["GPS GPSLatitude"])
                    lat_ref = str(tags.get("GPS GPSLatitudeRef", "N"))
                    if "S" in lat_ref:
                        lat = -lat
                    lon = self._convert_to_degrees(tags["GPS GPSLongitude"])
                    lon_ref = str(tags.get("GPS GPSLongitudeRef", "E"))
                    if "W" in lon_ref:
                        lon = -lon

                    if lat != 0.0 and lon != 0.0:
                        logger.log_info(f"GPS found for {img['filename']}")
                        record = {
                            "filename": img["filename"],
                            "path": img["path"],
                            "latitude": lat,
                            "longitude": lon,
                            "map_link": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}"
                        }
                        if "Image DateTime" in tags:
                            record["timestamp"] = str(tags["Image DateTime"])
                        if "Image Make" in tags:
                            record["camera_make"] = str(tags["Image Make"])
                        if "Image Model" in tags:
                            record["camera_model"] = str(tags["Image Model"])
                        results.append(record)
                    else:
                        logger.log_info(f"GPS not found or invalid for {img['filename']}")
                else:
                    logger.log_info(f"GPS not found for {img['filename']}")

                # Cleanup
                if local_tmp.exists():
                    local_tmp.unlink()
            except Exception as e:
                logger.log_error(f"Error parsing EXIF for {img['filename']}: {e}")

        logger.log_info(f"EXIF extraction: {len(results)} valid GPS tags found from {len(images)} images")

        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=4)
        except Exception as e:
            logger.log_error(f"Failed to save EXIF data: {e}")
        return out_path

    def _get_storage_lists(self, remote_path: str) -> tuple[list, dict]:
        """Gets raw file listings and hashes."""
        list_cmd = f'find {remote_path} -type f -exec stat -c "%n|%s|%Y" {{}} +'
        raw_listing = self.device.adb.shell(list_cmd).strip().splitlines()
        hash_cmd = f'find {remote_path} -type f -exec sha256sum {{}} +'
        raw_hashes = self.device.adb.shell(hash_cmd).strip().splitlines()
        hash_map = {}
        for line in raw_hashes:
            parts = line.split()
            if len(parts) >= 2:
                h, p = parts[0], " ".join(parts[1:])
                hash_map[p] = h
        return raw_listing, hash_map

    def _merge_storage_metadata(self, raw_listing: list, hash_map: dict) -> list:
        """Merges listing with hashes."""
        file_metadata = []
        for line in raw_listing:
            if "|" not in line:
                continue
            try:
                path_str, size, mtime = line.rsplit("|", 2)
                file_hash = hash_map.get(path_str, "HashError")
                file_metadata.append({
                    "filename": Path(path_str).name,
                    "path": path_str,
                    "size_bytes": int(size),
                    "modified_timestamp": int(mtime),
                    "sha256": file_hash
                })
            except ValueError:
                continue
        return file_metadata

    def extract_storage_metadata(
            self,
            remote_path: str = "/sdcard/",
            filename: str = "storage_metadata.json") -> Path:
        """Extracts and saves storage metadata."""
        output_path = self.output_dir / "media_metadata" / filename
        try:
            logger.log_info(f"Scanning storage at {remote_path} (optimized)...")
            raw_listing, hash_map = self._get_storage_lists(remote_path)
            file_metadata = self._merge_storage_metadata(raw_listing, hash_map)

            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(file_metadata, f, indent=4)

            logger.log_info(f"Storage metadata for {len(file_metadata)} files saved to: {output_path}")
            return output_path
        except Exception as e:
            logger.log_error(f"Failed to extract storage metadata: {e}")
            return output_path

    def _get_device_file_hash(self, remote_path: str) -> str:
        """
        Calculates the SHA-256 hash of a file directly on the Android device.
        """
        try:
            # We use sha256sum which is available on most modern Android
            # systems (Toybox)
            res = self.device.adb.shell(f"sha256sum '{remote_path}'")
            # Output format: <hash>  <path>
            return res.split()[0].strip()
        except Exception:
            return "HashError"

    def _discover_browser_history_path(self) -> Optional[str]:
        """
        Dynamically discovers the Chrome History DB path using adb shell find.
        Falls back to this if the default path is inaccessible.
        """
        try:
            output = self.device.adb.shell("find /data -name History 2>/dev/null").strip()
            for line in output.splitlines():
                if "com.android.chrome" in line:
                    return line.strip()
        except Exception as e:
            logger.log_error(f"Dynamic Chrome History discovery error: {e}")
        return None

    def _discover_calllog_db_path(self) -> Optional[str]:
        """
        Dynamically discovers the calllog.db path using adb shell find.
        Falls back to this if the default path is inaccessible.
        """
        try:
            output = self.device.adb.shell("find /data -name calllog.db 2>/dev/null").strip()
            for line in output.splitlines():
                if "com.android.providers.contacts" in line:
                    return line.strip()
        except Exception as e:
            logger.log_error(f"Dynamic calllog.db discovery error: {e}")
        return None

    def _acquire_physical_db(self, remote_path: str, local_db_path: Path) -> bool:
        """Pulls physical DB file."""
        try:
            self.device.adb.pull(remote_path, str(local_db_path))
        except Exception:
            pass
        return local_db_path.exists() and local_db_path.stat().st_size > 0

    def _parse_and_save_call_logs(self, local_db_path: Path, json_output_path: Path) -> Path:
        """Parses the local db and saves JSON."""
        hasher = ForensicHasher()
        db_hash = hasher.hash_file(local_db_path)
        logger.log_info(f"Database acquired. SHA-256: {db_hash}")

        logger.log_info("Parsing call records...")
        parser = CallLogParser(local_db_path)
        calls = parser.parse_calls()
        for c in calls:
            c["acquisition_method"] = "physical_sqlite"

        with open(json_output_path, "w", encoding="utf-8") as f:
            json.dump(calls, f, indent=4)
        logger.log_info(f"Successfully extracted {len(calls)} call records to {json_output_path}")
        return json_output_path

    def extract_call_logs(
            self,
            remote_path: str = "/data/user/0/com.android.providers.contacts/databases/calllog.db") -> Optional[Path]:
        """Orchestrates call log extraction with logical fallback."""
        local_db_path = self.output_dir / "call_log" / "calllog.db"
        json_output_path = self.output_dir / "call_log" / "call_logs.json"

        try:
            logger.log_info(f"Attempting to acquire call log database from {remote_path}...")
            if not self._acquire_physical_db(remote_path, local_db_path):
                discovered = self._discover_calllog_db_path()
                if discovered and discovered != remote_path:
                    logger.log_info(f"Call log DB discovered dynamically:\n{discovered}")
                    if not self._acquire_physical_db(discovered, local_db_path):
                        return self._extract_calls_via_content_provider(json_output_path)
                else:
                    return self._extract_calls_via_content_provider(json_output_path)
            else:
                logger.log_info(f"Default path success for calllog.db: {remote_path}")

            return self._parse_and_save_call_logs(local_db_path, json_output_path)
        except Exception as e:
            logger.log_warning(f"Error during call log extraction: {e}. Falling back.")
            return self._extract_calls_via_content_provider(json_output_path)

    def _parse_provider_call(self, line: str) -> dict:
        """Parses a single call log row from content provider."""
        call = {"number": "", "date": "", "duration": "", "type": "",
                "name": "", "acquisition_method": "logical_content_provider"}
        number_match = re.search(r'number=(.*?), ', line)
        date_match = re.search(r'date=(.*?), ', line)
        duration_match = re.search(r'duration=(.*?), ', line)
        type_match = re.search(r'type=(.*?), ', line)
        name_match = re.search(r'name=(.*?)(?:, [a-z_]+=|, _id=|$)', line)
        if number_match:
            call["number"] = number_match.group(1)
        if date_match:
            call["date"] = date_match.group(1)
        if duration_match:
            call["duration"] = duration_match.group(1)
        if type_match:
            call["type"] = type_match.group(1)
        if name_match:
            call["name"] = name_match.group(1) if name_match.group(1) != "null" else ""
        return call

    def _extract_calls_via_content_provider(self, json_output_path: Path) -> Optional[Path]:
        """Fallback method to extract call logs via Android content provider."""
        logger.log_info("Attempting logical extraction via content provider for Call Logs...")
        self.call_log_permission_denied = False
        try:
            output = self.device.adb.shell("content query --uri content://call_log/calls")
            if "SecurityException" in output and "READ_CALL_LOG" in output:
                logger.log_warning("Android provider permission denied: READ_CALL_LOG not granted.")
                self.call_log_permission_denied = True
                return None

            calls = [self._parse_provider_call(line) for line in output.splitlines() if line.startswith("Row: ")]

            with open(json_output_path, "w", encoding="utf-8") as f:
                json.dump(calls, f, indent=4)

            logger.log_info(f"Fallback successful: Extracted {len(calls)} call records via content provider.")
            return json_output_path
        except Exception as e:
            logger.log_error(f"Logical extraction for Call Logs failed: {e}")
            return None

    def _parse_and_save_sms(self, local_db_path: Path, json_output_path: Path) -> Path:
        """Parses the local sms db and saves JSON."""
        hasher = ForensicHasher()
        db_hash = hasher.hash_file(local_db_path)
        logger.log_info(f"SMS database acquired. SHA-256: {db_hash}")

        logger.log_info("Parsing SMS records...")
        parser = SMSParser(local_db_path)
        messages = parser.parse_messages()
        for m in messages:
            m["acquisition_method"] = "physical_sqlite"

        with open(json_output_path, "w", encoding="utf-8") as f:
            json.dump(messages, f, indent=4)
        logger.log_info(f"Successfully extracted {len(messages)} SMS records to {json_output_path}")
        return json_output_path

    def extract_sms(
            self,
            remote_path: str = "/data/data/com.android.providers.telephony/"
                               "databases/mmssms.db"
    ) -> Optional[Path]:
        """Orchestrates SMS extraction with logical fallback."""
        local_db_path = self.output_dir / "sms" / "mmssms.db"
        json_output_path = self.output_dir / "sms" / "sms_messages.json"

        try:
            logger.log_info(f"Attempting to acquire SMS database from {remote_path}...")
            if not self._acquire_physical_db(remote_path, local_db_path):
                logger.log_warning("Acquisition failed or DB is 0 bytes. Falling back to logical content provider.")
                return self._extract_sms_via_content_provider(json_output_path)

            return self._parse_and_save_sms(local_db_path, json_output_path)
        except Exception as e:
            if "Permission denied" in str(e) or "does not exist" in str(e).lower():
                logger.log_warning(f"Could not access {remote_path}. Falling back.")
                return self._extract_sms_via_content_provider(json_output_path)
            logger.log_error(f"Unexpected error during SMS extraction: {e}")
            return None

    def _parse_provider_sms(self, line: str) -> dict:
        """Parses a single SMS log row from content provider."""
        msg = {"address": "", "date": "", "body": "", "type": "",
               "read": "", "acquisition_method": "logical_content_provider"}
        address_match = re.search(r'address=(.*?), ', line)
        date_match = re.search(r'date=(.*?), ', line)
        type_match = re.search(r'type=(.*?), ', line)
        read_match = re.search(r'read=(.*?), ', line)
        body_match = re.search(r'body=(.*?)(?:, [a-z_]+=|, _id=|$)', line)
        if address_match:
            msg["address"] = address_match.group(1)
        if date_match:
            msg["date"] = date_match.group(1)
        if body_match:
            msg["body"] = body_match.group(1)
        if type_match:
            msg["type"] = type_match.group(1)
        if read_match:
            msg["read"] = read_match.group(1)
        return msg

    def _extract_sms_via_content_provider(self, json_output_path: Path) -> Optional[Path]:
        """Fallback method to extract SMS via Android content provider."""
        logger.log_info("Attempting logical extraction via content provider for SMS...")
        try:
            output = self.device.adb.shell("content query --uri content://sms")
            messages = [self._parse_provider_sms(line) for line in output.splitlines() if line.startswith("Row: ")]

            with open(json_output_path, "w", encoding="utf-8") as f:
                json.dump(messages, f, indent=4)

            logger.log_info(f"Fallback successful: Extracted {len(messages)} SMS records via content provider.")
            return json_output_path
        except Exception as e:
            logger.log_error(f"Logical extraction for SMS failed: {e}")
            return None

    def _parse_and_save_browser(self, local_db_path: Path, json_output_path: Path) -> Path:
        """Parses browser DB and saves to JSON."""
        hasher = ForensicHasher()
        db_hash = hasher.hash_file(local_db_path)
        logger.log_info(f"Browser history acquired. SHA-256: {db_hash}")

        logger.log_info("Parsing browser history records...")
        parser = BrowserParser(local_db_path)
        history = parser.parse_history()

        with open(json_output_path, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=4)
        logger.log_info(f"Successfully extracted {len(history)} records to {json_output_path}")
        return json_output_path

    def extract_browser_history(
            self,
            remote_path: str = "/data/user/0/com.android.chrome/app_chrome/Default/History"
    ) -> Optional[Path]:
        """Extracts the Chrome history database."""
        local_db_path = self.output_dir / "browser_history" / "Chrome_History"
        json_output_path = self.output_dir / "browser_history" / "browser_history.json"

        try:
            logger.log_info(f"Attempting to acquire Chrome history from {remote_path}...")
            discovered = None
            try:
                self.device.adb.pull(remote_path, str(local_db_path))
            except Exception:
                pass

            if not local_db_path.exists() or local_db_path.stat().st_size == 0:
                discovered = self._discover_browser_history_path()
                if discovered and discovered != remote_path:
                    logger.log_info(f"Browser history DB discovered dynamically:\n{discovered}")
                    try:
                        self.device.adb.pull(discovered, str(local_db_path))
                    except Exception:
                        pass

            if not local_db_path.exists() or local_db_path.stat().st_size == 0:
                logger.log_error("Acquisition failed: Chrome history file was not downloaded.")
                return None
            else:
                if not discovered:
                    logger.log_info(f"Default path success for browser history: {remote_path}")

            return self._parse_and_save_browser(local_db_path, json_output_path)
        except Exception as e:
            logger.log_error(f"Unexpected error during browser history extraction: {e}")
            return None

    def extract_whatsapp(
            self,
            remote_path: str = "/data/data/com.whatsapp/databases/msgstore.db.crypt15") -> Optional[Path]:
        """Attempt WhatsApp DB acquisition."""
        local_db_path = self.output_dir / "whatsapp" / "msgstore.db.crypt15"
        try:
            logger.log_info(
                f"Attempting to acquire WhatsApp database from {remote_path}...")
            self.device.adb.pull(remote_path, str(local_db_path))

            if not local_db_path.exists() or local_db_path.stat().st_size == 0:
                logger.log_warning(
                    "WhatsApp databases inaccessible on non-rooted production emulator.")
                return None

            hasher = ForensicHasher()
            db_hash = hasher.hash_file(local_db_path)
            logger.log_info(f"WhatsApp database acquired. SHA-256: {db_hash}")
            return local_db_path
        except Exception as e:
            if "Permission denied" in str(
                    e) or "does not exist" in str(e).lower():
                logger.log_warning(
                    "WhatsApp databases inaccessible on non-rooted production emulator.")
            else:
                logger.log_error(f"WhatsApp extraction failed: {e}")
            return None
