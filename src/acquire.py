import argparse
import sys
import json
from datetime import datetime, timezone
from pathlib import Path
from .logger import ForensicLogger
from .device import AndroidDeviceManager
from .extractor import DataExtractor
from .reporter import ForensicReporter
from .utils import EvidenceManager
from .hasher import ForensicHasher


def setup_argparse() -> argparse.Namespace:
    """Configures and parses command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Android Forensic Acquisition Tool - CLI.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("--case", required=True, help="Case identifier.")
    parser.add_argument("--investigator", required=True, help="Investigator.")
    parser.add_argument("--output", type=Path, default=Path("./output"),
                        help="Output root.")
    parser.add_argument("--serial", help="Target device serial.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate only.")
    parser.add_argument(
        "--version",
        action="version",
        version="Antigravity Forensic Acquisition Tool v1.0")

    return parser.parse_args()


def _check_zero_byte(
        file_path: Path,
        artefact_name: str,
        timeline: list,
        add_event,
        fallback_occurred: bool = False) -> None:
    """
    Forensic guard: if a pulled database file exists but has 0 bytes,
    it means ADB created an empty placeholder due to a permission denial.
    This is documented as a forensic alert in the acquisition timeline.
    """
    if (file_path.exists() and file_path.stat().st_size == 0) or fallback_occurred:
        alert = (
            f"Forensic Alert: {artefact_name} database physical extraction failed (requires root). "
        )
        if fallback_occurred:
            alert += "Fallback to logical acquisition via Android content providers was activated."
        add_event(alert)


def main() -> None:
    """Main orchestration for forensic acquisition."""
    args = setup_argparse()
    logger = ForensicLogger()

    print("\n[1/5] Initializing Device Connection...")
    manager = AndroidDeviceManager()
    device = manager.connect_device(serial=args.serial)

    if not device:
        print("ERROR: No Android device detected. Check connection.")
        sys.exit(1)

    metadata = device.fetch_metadata()
    print("\n--- Device Detected ---")
    print(f"Model: {metadata.get('model')}")
    print(f"Android Version: {metadata.get('android_version')}")
    print(f"Serial: {metadata.get('serial_number')}")
    print(f"Device Time: {metadata.get('device_time')}")
    print("-----------------------")

    choice = input("Proceed with acquisition? (Y/N): ").strip().upper()
    if choice != "Y":
        print("Acquisition aborted by investigator.")
        sys.exit(0)

    # --- FORENSIC REQUIREMENT: Calculate and log device clock drift ---
    drift_ms = device.calculate_clock_drift()
    if drift_ms is not None:
        print(
            f"[*] Clock Drift: {drift_ms:+.3f}ms (logged to acquisition.log)")

    if args.dry_run:
        print("\nDRY RUN complete. Device is reachable.")
        return

    print("\n[2/5] Creating Evidence Structure...")
    paths = EvidenceManager.create_structure(args.output, device.serial)
    logger.set_log_file(paths.log_file)

    timeline = []

    def add_event(msg: str):
        # Use millisecond-accurate UTC format matching the ForensicLogger (ISO
        # 8601 + 'Z')
        now = datetime.now(timezone.utc)
        ts = now.strftime("%Y-%m-%dT%H:%M:%S.") + \
            f"{now.microsecond // 1000:03d}Z"
        event = {"timestamp": ts, "message": msg}
        timeline.append(event)
        logger.log_info(msg)

    start_time = datetime.now(timezone.utc)
    add_event(f"Acquisition started for Case: {args.case}")
    add_event(f"Tool Startup: Antigravity Forensic Acquisition Tool v1.0")
    add_event(f"CLI Arguments: case={args.case}, investigator={args.investigator}, serial={args.serial}, dry_run={args.dry_run}")
    add_event(f"Device Connection: Model={metadata.get('model')}, Serial={metadata.get('serial_number')}, Android Version={metadata.get('android_version')}")
    add_event(f"Investigator confirmation: Investigator {args.investigator} authorized acquisition.")

    print("[3/5] Performing Logical Extraction...")
    extractor = DataExtractor(device, paths.artefacts)

    # 3.1 Extract Installed Apps
    add_event("Extracting installed applications...")
    extractor.extract_apps_to_json(
        paths.sub_artefacts["installed_apps"] / "apps.json"
    )

    # 3.2 Extract Call Logs
    add_event("Extracting call log database...")
    # Saves to artefacts/call_logs.json
    call_logs_json = extractor.extract_call_logs()
    fallback_call_logs = False
    if call_logs_json and call_logs_json.exists():
        try:
            with open(call_logs_json, "r") as f:
                data = json.load(f)
                if data and len(data) > 0 and data[0].get(
                        "acquisition_method") == "logical_content_provider":
                    fallback_call_logs = True
        except Exception:
            pass
    _check_zero_byte(
        paths.sub_artefacts["call_log"] /
        "contacts2.db",
        "Call Log",
        timeline,
        add_event,
        fallback_occurred=fallback_call_logs)
    if getattr(extractor, "call_log_permission_denied", False):
        add_event(
            "Android provider permission denied: READ_CALL_LOG not granted to adb shell context.")

    # 3.3 Extract SMS
    add_event("Extracting SMS database...")
    sms_json = extractor.extract_sms()  # Saves to artefacts/sms_messages.json
    fallback_sms = False
    if sms_json and sms_json.exists():
        try:
            with open(sms_json, "r") as f:
                data = json.load(f)
                if data and len(data) > 0 and data[0].get(
                        "acquisition_method") == "logical_content_provider":
                    fallback_sms = True
        except Exception:
            pass
    _check_zero_byte(
        paths.artefacts /
        "mmssms.db",
        "SMS",
        timeline,
        add_event,
        fallback_occurred=fallback_sms)

    # 3.4 Extract Browser History
    add_event("Extracting Chrome history...")
    extractor.extract_browser_history()  # Saves to artefacts/browser_history.json
    _check_zero_byte(
        paths.artefacts /
        "Chrome_History",
        "Browser History",
        timeline,
        add_event)

    # 3.5 Extract WhatsApp
    add_event("Extracting WhatsApp databases...")
    whatsapp_path = extractor.extract_whatsapp()
    if not whatsapp_path:
        add_event(
            "WhatsApp databases inaccessible on non-rooted production emulator.")

    # 3.6 Map External Storage
    add_event("Mapping external storage metadata...")
    extractor.extract_storage_metadata(filename="storage_manifest.json")

    print("[4/5] Verifying Data Integrity...")
    hasher = ForensicHasher()
    integrity_manifest = hasher.hash_directory(paths.artefacts)
    hasher.update_manifest(paths.manifest, integrity_manifest)

    # Prepare integrity data for report
    report_integrity = [{"filename": k, "hash": v}
                        for k, v in integrity_manifest.items()]
                        
    total_evidence_size = 0
    total_file_count = 0
    for rel_path, expected_hash in integrity_manifest.items():
        artefact_path = paths.artefacts / rel_path
        fsize = artefact_path.stat().st_size if artefact_path.exists() else 0
        total_evidence_size += fsize
        total_file_count += 1
        add_event(f"Artefact extracted: {rel_path} | Size: {fsize} bytes | SHA256: {expected_hash}")

    print("[5/5] Generating Forensic Reports...")
    reporter = ForensicReporter(template_dir=Path("./templates"))

    end_time = datetime.now(timezone.utc)
    duration_str = str(end_time - start_time).split('.')[0]

    case_data = {
        "case_id": args.case,
        "investigator": args.investigator,
        "device_serial": metadata.get("serial_number"),
        "device_model": metadata.get("model"),
        "android_version": metadata.get("android_version"),
        "start_time": start_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "end_time": end_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration": duration_str
    }

    evidence_summary = {
        "call_logs": [],
        "sms_messages": [],
        "installed_apps": [],
        "whatsapp_accessible": bool(whatsapp_path)}

    call_log_path = paths.sub_artefacts["call_log"] / "call_logs.json"
    if call_log_path.exists():
        with open(call_log_path, "r") as f:
            evidence_summary["call_logs"] = json.load(f)

    sms_path = paths.artefacts / "sms_messages.json"
    if sms_path.exists():
        with open(sms_path, "r") as f:
            evidence_summary["sms_messages"] = json.load(f)

    apps_path = paths.sub_artefacts["installed_apps"] / "apps.json"
    if apps_path.exists():
        with open(apps_path, "r") as f:
            evidence_summary["installed_apps"] = json.load(f)

    reporter.generate_html_report(paths.report_html, case_data,
                                  evidence_summary, report_integrity,
                                  timeline, artefacts_dir=paths.artefacts)
    reporter.generate_json_report(paths.report_json, case_data,
                                  evidence_summary)

    print("\n[Final] Verifying Final Evidence Integrity...")

    verification_success = True
    for rel_path, expected_hash in integrity_manifest.items():
        actual_hash = hasher.hash_file(paths.artefacts / rel_path)
        if actual_hash != expected_hash:
            logger.log_error(f"INTEGRITY FAILURE: {rel_path} has changed!")
            verification_success = False

    if verification_success:
        add_event("Final integrity verification passed.")
    else:
        add_event("CRITICAL: Integrity verification failed.")

    add_event(f"Acquisition Completion: Total duration: {duration_str}, Total files: {total_file_count}, Total evidence size: {total_evidence_size} bytes")
    add_event("Acquisition process completed successfully.")
    
    # F. acquisition.log integrity
    log_hash_initial = hasher.hash_file(paths.log_file)
    add_event(f"acquisition.log SHA256 computed: {log_hash_initial}")
    
    log_hash_final = hasher.hash_file(paths.log_file)
    with open(paths.integrity / "acquisition_hash.txt", "w") as f:
        f.write(f"SHA-256 of acquisition.log: {log_hash_final}\n")
    print("\n--- SUCCESS ---")
    print(f"Report: {paths.report_html.absolute()}")
    print(f"Hashes: {(paths.integrity / 'acquisition_hash.txt').absolute()}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAcquisition interrupted by user.")
    except Exception as e:
        print(f"\nCRITICAL ERROR: {e}")
