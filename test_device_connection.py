import sys
from pathlib import Path
from typing import Optional, Dict

# Attempt to import adb_shell; provide clear error if missing
try:
    from adb_shell.adb_device import AdbDeviceUsb
    from adb_shell.auth.sign_pythonrsa import PythonRSASigner
    from adb_shell.auth.keygen import keygen
except ImportError:
    print("ERROR: 'adb-shell' library not found.")
    print("Please install it using: pip install adb-shell[usb]")
    sys.exit(1)


def get_adb_keys() -> list[PythonRSASigner]:
    """
    Locates or generates ADB RSA keys for authentication.
    """
    key_path = Path.home() / ".android" / "adbkey"
    keys = []

    if not key_path.exists():
        print(f"[*] No ADB keys found at {key_path}. Generating new keys...")
        key_path.parent.mkdir(parents=True, exist_ok=True)
        keygen(str(key_path))

    try:
        with open(key_path, 'r') as f:
            priv = f.read()
        with open(str(key_path) + ".pub", 'r') as f:
            pub = f.read()
        keys.append(PythonRSASigner(pub, priv))
    except Exception as e:
        print(f"[!] Error loading ADB keys: {e}")

    return keys


def test_connection() -> None:
    """
    Attempts to connect to a USB Android device and print forensic metadata.
    """
    print("=== Android Device Connection Test ===")
    
    try:
        # Initialize device
        device = AdbDeviceUsb()
        rsa_keys = get_adb_keys()

        print("[*] Searching for USB device and authenticating...")
        # Connect with timeout
        device.connect(rsa_keys=rsa_keys, auth_timeout_s=30)
        
        # Retrieve metadata
        print("[+] Connection Successful!\n")
        
        # We use adb shell commands for retrieval
        serial = device.shell("getprop ro.serialno").strip()
        model = device.shell("getprop ro.product.model").strip()
        manufacturer = device.shell("getprop ro.product.manufacturer").strip()
        version = device.shell("getprop ro.build.version.release").strip()
        
        # Battery level parsing - More robust approach
        battery_output = device.shell("dumpsys battery")
        battery_level = "Unknown"
        for line in battery_output.splitlines():
            if "level:" in line.lower():
                # Extract digits only to avoid trailing text
                parts = line.split(":")
                if len(parts) > 1:
                    battery_level = "".join(filter(str.isdigit, parts[1]))
                    break
        
        # Current device time
        device_time = device.shell("date '+%Y-%m-%d %H:%M:%S UTC'").strip()

        # Display results
        print("-" * 40)
        print(f"Serial Number : {serial}")
        print(f"Model         : {model}")
        print(f"Manufacturer  : {manufacturer}")
        print(f"Android Ver   : {version}")
        print(f"Battery Level : {battery_level}%")
        print(f"Device Time   : {device_time}")
        print("-" * 40)

        device.close()

    except Exception as e:
        print(f"\n[!] CONNECTION FAILED")
        if "Device not found" in str(e):
            print("ERROR: No Android device detected via USB.")
        elif "authentication" in str(e).lower():
            print("ERROR: Authentication failed. Please accept the RSA popup on the device.")
        else:
            print(f"Details: {e}")
        sys.exit(1)


if __name__ == "__main__":
    test_connection()
