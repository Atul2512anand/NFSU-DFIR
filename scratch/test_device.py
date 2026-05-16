import sys
from pathlib import Path

# Add src to path so we can import device
sys.path.append(str(Path.cwd()))

from src.device import AndroidDeviceManager

def test_device_detection():
    print("--- Android Device Detection Test ---")
    
    manager = AndroidDeviceManager()
    
    print("Connecting to device via USB...")
    device = manager.connect_device()
    
    if not device:
        print("ERROR: Could not connect to any device.")
        print("Check if:")
        print("1. Device is plugged in via USB.")
        print("2. USB Debugging is enabled on the device.")
        print("3. You have the necessary USB drivers (libusb1).")
        return

    print("Connection successful. Verifying responsiveness...")
    if not manager.confirm_device():
        print("WARNING: Device connected but not responsive/authorized.")
        print("Check if you need to allow USB debugging on the device screen.")
        return

    print("Fetching metadata...")
    metadata = manager.get_device_metadata()
    
    if "error" in metadata:
        print(f"ERROR: {metadata['error']}")
        return

    print("\nDevice Info:")
    print(f"  Model:           {metadata.get('model')}")
    print(f"  Manufacturer:    {metadata.get('manufacturer')}")
    print(f"  Serial:          {metadata.get('serial_number')}")
    print(f"  Android Version: {metadata.get('android_version')}")
    print(f"  Device Time:     {metadata.get('device_time')}")
    print("\nTest completed successfully.")

if __name__ == "__main__":
    try:
        test_device_detection()
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
