"""
Module for forensic acquisition.
"""

from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Optional, Any, List
from adb_shell.adb_device import AdbDeviceTcp
from adb_shell.auth.sign_pythonrsa import PythonRSASigner
from adb_shell.auth.keygen import keygen
from .logger import ForensicLogger

# Initialize logger for this module
logger = ForensicLogger()


class AndroidDevice:
    """
    Represents a connected Android device and its metadata.
    Uses adb-shell for direct communication without subprocess.
    """

    def __init__(self, adb_device: AdbDeviceTcp, serial: str):
        """Function documentation."""

        self.adb = adb_device
        self.serial = serial
        self.metadata: Dict[str, str] = {}

    def fetch_metadata(self) -> Dict[str, str]:
        """
        Retrieves device properties and current time from the device.
        """
        try:
            self.metadata = {
                "serial_number": self.serial,
                "model": self.adb.shell("getprop ro.product.model").strip(),
                "manufacturer": self.adb.shell(
                    "getprop ro.product.manufacturer").strip(),
                "android_version": self.adb.shell(
                    "getprop ro.build.version.release").strip(),
                "device_time": self.adb.shell("date +%Y-%m-%dT%H:%M:%S").strip(),
            }
            logger.log_info(f"Metadata retrieved for device {self.serial}")
            return self.metadata
        except Exception as e:
            logger.log_error(f"Failed to fetch metadata: {e}")
            return {"serial_number": self.serial, "error": str(e)}

    def calculate_clock_drift(self) -> Optional[float]:
        """
        Calculates the clock drift between the device and the forensic workstation.

        Compares 'adb shell date' (device UTC time) against the local system UTC
        time captured immediately before and after the shell call to account for
        round-trip latency.

        Returns:
            float: Drift in milliseconds (positive = device is ahead,
                   negative = device is behind). None on error.
        """
        try:
            # Capture local time immediately before the shell call
            local_before = datetime.now(timezone.utc)

            # Request Unix epoch seconds (integer) from the device for
            # precision
            raw = self.adb.shell("date +%s").strip()

            # Capture local time immediately after the shell call
            local_after = datetime.now(timezone.utc)

            # Estimate the time the device command ran (midpoint of round-trip)
            local_midpoint = local_before + (local_after - local_before) / 2

            device_time = datetime.fromtimestamp(int(raw), tz=timezone.utc)
            drift_ms = (device_time - local_midpoint).total_seconds() * 1000

            logger.log_info(
                f"[CLOCK DRIFT] Device serial={self.serial} | "
                f"Device UTC={device_time.isoformat()} | "
                f"System UTC={local_midpoint.isoformat()} | "
                f"Drift={drift_ms:+.3f}ms"
            )
            return drift_ms

        except Exception as e:
            logger.log_error(
                f"[CLOCK DRIFT] Failed to calculate clock drift for "
                f"{self.serial}: {e}"
            )
            return None


class AndroidDeviceManager:
    """
    Manages connections and discovery for Android devices using adb-shell.
    """

    def __init__(self):
        """Function documentation."""

        self.current_device: Optional[AndroidDevice] = None

    def _get_adb_keys(self) -> List[PythonRSASigner]:
        """
        Locates or generates ADB keys for authentication.
        """
        keys = []
        key_path = Path.home() / ".android" / "adbkey"

        # 1. Try to load existing keys
        if key_path.exists():
            try:
                with open(key_path, 'r') as f:
                    priv = f.read()
                with open(str(key_path) + ".pub", 'r') as f:
                    pub = f.read()
                keys.append(PythonRSASigner(pub, priv))
                return keys
            except Exception:
                pass

        # 2. Generate new keys if none found (Forensic standard)
        try:
            logger.log_info(
                "No existing keys found. Generating new forensic RSA keys...")
            key_path.parent.mkdir(parents=True, exist_ok=True)
            keygen(str(key_path))
            with open(key_path, 'r') as f:
                priv = f.read()
            with open(str(key_path) + ".pub", 'r') as f:
                pub = f.read()
            keys.append(PythonRSASigner(pub, priv))
        except Exception as e:
            logger.log_error(f"Failed to generate forensic keys: {e}")

        return keys

    def connect_device(self, serial: Optional[str] = None,
                       auth_timeout_s: int = 30) -> Optional["AndroidDevice"]:
        """
        Attempts to connect to an Android device via USB with RSA authentication.
        Args:
            auth_timeout_s: How long to wait for the 'Allow USB Debugging' popup.
                            Use a short value (5s) for scan, longer (30s) for acquisition.
        """
        try:
            rsa_keys = self._get_adb_keys()
            if not rsa_keys:
                logger.log_warning(
                    "No ADB keys found. You may need to run 'adb devices' "
                    "once on your PC to generate them."
                )

            device = AdbDeviceTcp("127.0.0.1", 5555)
            device.connect(rsa_keys=rsa_keys, auth_timeout_s=auth_timeout_s)

            # ── Liveness check: verify the device actually responds ──────
            # This catches ghost USB handles where connect() succeeds but
            # the phone is not actually present or authorised.
            try:
                response = device.shell("echo alive", timeout_s=5).strip()
                if response != "alive":
                    raise RuntimeError("Device liveness check failed.")
            except Exception as ping_err:
                logger.log_error(
                    f"Device connected but failed liveness check: {ping_err}")
                try:
                    device.close()
                except Exception:
                    pass
                return None

            actual_serial = serial or "USB_DEVICE"
            self.current_device = AndroidDevice(device, actual_serial)
            logger.log_info(f"Successfully authenticated: {actual_serial}")
            return self.current_device

        except Exception as e:
            logger.log_error(f"Device connection failed: {e}")
            return None

    def confirm_device(self) -> bool:
        """
        Verifies if the current device is responsive and authorized.
        """
        if not self.current_device or not self.current_device.adb:
            return False

        try:
            # Simple command to check responsiveness
            res = self.current_device.adb.shell("echo 1")
            return res.strip() == "1"
        except Exception:
            return False

    def get_device_metadata(self) -> Dict[str, Any]:
        """
        Returns a dictionary of all relevant forensic metadata for the device.
        """
        if not self.current_device:
            return {"error": "No device connected"}

        return self.current_device.fetch_metadata()
