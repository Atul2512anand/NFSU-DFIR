"""
Module for forensic acquisition.
"""

import json
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

    def extract_storage_metadata(
            self,
            remote_path: str = "/sdcard/",
            filename: str = "storage_metadata.json") -> Path:
        """
        Recursively lists all files in the specified remote directory and
        collects metadata. Calculates SHA-256 hashes in batches for speed.
        """
        output_path = self.output_dir / filename
        file_metadata = []

        try:
            logger.log_info(
                f"Scanning storage at {remote_path} (optimized)..."
            )

            # 1. Get file listing with Size and ModTime
            # Format: path|size|mtime
            list_cmd = (f'find {remote_path} -type f '
                        f'-exec stat -c "%n|%s|%Y" {{}} +')
            raw_listing = self.device.adb.shell(list_cmd).strip().splitlines()

            # 2. Get file hashes in batches
            # Format: hash  path
            hash_cmd = f'find {remote_path} -type f -exec sha256sum {{}} +'
            raw_hashes = self.device.adb.shell(hash_cmd).strip().splitlines()

            # Create a lookup map for hashes
            hash_map = {}
            for line in raw_hashes:
                parts = line.split()
                if len(parts) >= 2:
                    h, p = parts[0], " ".join(parts[1:])
                    hash_map[p] = h

            # 3. Merge metadata
            for line in raw_listing:
                if "|" not in line:
                    continue

                # Use rsplit to handle filenames with pipes
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

            # Save to JSON
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(file_metadata, f, indent=4)

            logger.log_info(
                f"Storage metadata for {len(file_metadata)} files "
                f"saved to: {output_path}"
            )
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

    def extract_call_logs(
            self,
            remote_path: str = "/data/data/com.android.providers.contacts/databases/contacts2.db") -> Optional[Path]:
        """
        Extracts the call log database, verifies integrity, and parses records.
        Handles permission errors gracefully for non-rooted devices.
        """
        local_db_path = self.output_dir / "call_log" / "contacts2.db"
        json_output_path = self.output_dir / "call_log" / "call_logs.json"

        try:
            logger.log_info(
                f"Attempting to acquire call log database from {remote_path}...")

            # 1. Pull the raw database file
            # Note: adb-shell pull requires the file to be accessible by the
            # adb user
            self.device.adb.pull(remote_path, str(local_db_path))

            if not local_db_path.exists() or local_db_path.stat().st_size == 0:
                logger.log_warning(
                    "Acquisition failed or DB is 0 bytes. Falling back to logical content provider.")
                return self._extract_calls_via_content_provider(
                    json_output_path)

            # 2. Establish Integrity (Hash immediately)
            hasher = ForensicHasher()
            db_hash = hasher.hash_file(local_db_path)
            logger.log_info(f"Database acquired. SHA-256: {db_hash}")

            # 3. Parse Records
            logger.log_info("Parsing call records...")
            parser = CallLogParser(local_db_path)
            calls = parser.parse_calls()

            for c in calls:
                c["acquisition_method"] = "physical_sqlite"

            # 4. Export to JSON
            with open(json_output_path, "w", encoding="utf-8") as f:
                json.dump(calls, f, indent=4)

            logger.log_info(
                f"Successfully extracted {len(calls)} call records to {json_output_path}")
            return json_output_path

        except Exception as e:
            if "Permission denied" in str(
                    e) or "does not exist" in str(e).lower():
                logger.log_warning(
                    f"Could not access {remote_path}. Device may not "
                    "be rooted or path is incorrect. Falling back."
                )
                return self._extract_calls_via_content_provider(
                    json_output_path)
            else:
                logger.log_error(
                    f"Unexpected error during call log extraction: {e}"
                )
            return None

    def _extract_calls_via_content_provider(
            self, json_output_path: Path) -> Optional[Path]:
        """Fallback method to extract call logs via Android content provider."""
        logger.log_info(
            "Attempting logical extraction via content provider for Call Logs...")
        self.call_log_permission_denied = False
        try:
            output = self.device.adb.shell(
                "content query --uri content://call_log/calls")
            if "SecurityException" in output and "READ_CALL_LOG" in output:
                logger.log_warning(
                    "Android provider permission denied: READ_CALL_LOG not granted to adb shell context.")
                self.call_log_permission_denied = True
                return None

            calls = []
            for line in output.splitlines():
                if not line.startswith("Row: "):
                    continue

                call = {
                    "number": "",
                    "date": "",
                    "duration": "",
                    "type": "",
                    "name": "",
                    "acquisition_method": "logical_content_provider"
                }

                number_match = re.search(r'number=(.*?), ', line)
                date_match = re.search(r'date=(.*?), ', line)
                duration_match = re.search(r'duration=(.*?), ', line)
                type_match = re.search(r'type=(.*?), ', line)
                name_match = re.search(
                    r'name=(.*?)(?:, [a-z_]+=|, _id=|$)', line)

                if number_match:
                    call["number"] = number_match.group(1)
                if date_match:
                    call["date"] = date_match.group(1)
                if duration_match:
                    call["duration"] = duration_match.group(1)
                if type_match:
                    call["type"] = type_match.group(1)
                if name_match:
                    name_val = name_match.group(1)
                    call["name"] = name_val if name_val != "null" else ""

                calls.append(call)

            with open(json_output_path, "w", encoding="utf-8") as f:
                json.dump(calls, f, indent=4)

            logger.log_info(
                f"Fallback successful: Extracted {len(calls)} call records via content provider.")
            return json_output_path
        except Exception as e:
            logger.log_error(f"Logical extraction for Call Logs failed: {e}")
            return None

    def extract_sms(
            self,
            remote_path: str = "/data/data/com.android.providers.telephony/"
                               "databases/mmssms.db"
    ) -> Optional[Path]:
        """
        Extracts the SMS database, verifies integrity, and parses messages.
        Handles permission errors gracefully for non-rooted devices.
        """
        local_db_path = self.output_dir / "mmssms.db"
        json_output_path = self.output_dir / "sms_messages.json"

        try:
            logger.log_info(
                f"Attempting to acquire SMS database from {remote_path}..."
            )

            # 1. Pull the raw database file
            self.device.adb.pull(remote_path, str(local_db_path))

            if not local_db_path.exists() or local_db_path.stat().st_size == 0:
                logger.log_warning(
                    "Acquisition failed or DB is 0 bytes. Falling back to logical content provider."
                )
                return self._extract_sms_via_content_provider(json_output_path)

            # 2. Establish Integrity (Hash immediately)
            hasher = ForensicHasher()
            db_hash = hasher.hash_file(local_db_path)
            logger.log_info(f"SMS database acquired. SHA-256: {db_hash}")

            # 3. Parse Records
            logger.log_info("Parsing SMS records...")
            parser = SMSParser(local_db_path)
            messages = parser.parse_messages()

            for m in messages:
                m["acquisition_method"] = "physical_sqlite"

            # 4. Export to JSON
            with open(json_output_path, "w", encoding="utf-8") as f:
                json.dump(messages, f, indent=4)

            logger.log_info(
                f"Successfully extracted {len(messages)} SMS records "
                f"to {json_output_path}"
            )
            return json_output_path

        except Exception as e:
            if "Permission denied" in str(
                    e) or "does not exist" in str(e).lower():
                logger.log_warning(
                    f"Could not access {remote_path}. SMS data "
                    "usually requires root access. Falling back."
                )
                return self._extract_sms_via_content_provider(json_output_path)
            else:
                logger.log_error(
                    f"Unexpected error during SMS extraction: {e}")
            return None

    def _extract_sms_via_content_provider(
            self, json_output_path: Path) -> Optional[Path]:
        """Fallback method to extract SMS via Android content provider."""
        logger.log_info(
            "Attempting logical extraction via content provider for SMS...")
        try:
            output = self.device.adb.shell("content query --uri content://sms")
            messages = []
            for line in output.splitlines():
                if not line.startswith("Row: "):
                    continue

                msg = {
                    "address": "",
                    "date": "",
                    "body": "",
                    "type": "",
                    "read": "",
                    "acquisition_method": "logical_content_provider"
                }

                address_match = re.search(r'address=(.*?), ', line)
                date_match = re.search(r'date=(.*?), ', line)
                type_match = re.search(r'type=(.*?), ', line)
                read_match = re.search(r'read=(.*?), ', line)
                body_match = re.search(
                    r'body=(.*?)(?:, [a-z_]+=|, _id=|$)', line)

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

                messages.append(msg)

            with open(json_output_path, "w", encoding="utf-8") as f:
                json.dump(messages, f, indent=4)

            logger.log_info(
                f"Fallback successful: Extracted {len(messages)} SMS records via content provider.")
            return json_output_path
        except Exception as e:
            logger.log_error(f"Logical extraction for SMS failed: {e}")
            return None

    def extract_browser_history(
            self,
            remote_path: str = "/data/data/com.android.chrome/app_chrome/"
                               "Default/History"
    ) -> Optional[Path]:
        """
        Extracts the Chrome history database, verifies integrity, and parses.
        Handles permission errors gracefully for non-rooted devices.
        """
        local_db_path = self.output_dir / "Chrome_History"
        json_output_path = self.output_dir / "browser_history.json"

        try:
            logger.log_info(
                f"Attempting to acquire Chrome history from {remote_path}..."
            )

            # 1. Pull the raw History file
            self.device.adb.pull(remote_path, str(local_db_path))

            if not local_db_path.exists():
                logger.log_error(
                    "Acquisition failed: Chrome history file was not downloaded."
                )
                return None

            # 2. Establish Integrity (Hash immediately)
            hasher = ForensicHasher()
            db_hash = hasher.hash_file(local_db_path)
            logger.log_info(f"Browser history acquired. SHA-256: {db_hash}")

            # 3. Parse Records
            logger.log_info("Parsing browser history records...")
            parser = BrowserParser(local_db_path)
            history = parser.parse_history()

            # 4. Export to JSON
            with open(json_output_path, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=4)

            logger.log_info(
                f"Successfully extracted {len(history)} records "
                f"to {json_output_path}"
            )
            return json_output_path

        except Exception as e:
            if "Permission denied" in str(
                    e) or "does not exist" in str(e).lower():
                logger.log_warning(
                    f"Could not access {remote_path}. Chrome history "
                    "usually requires root access."
                )
            else:
                logger.log_error(
                    f"Unexpected error during browser history extraction: {e}"
                )

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
