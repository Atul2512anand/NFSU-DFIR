"""
Module for forensic acquisition.
"""

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
    parser.add_argument("--case", required=True, help="Case reference number (e.g. DFIR-2024-0147)")
    parser.add_argument("--investigator", required=True, help="Name of the acquiring investigator")
    parser.add_argument("--output", type=Path, default=Path("./output"), help="Output directory root")
    parser.add_argument("--platform", choices=["android", "ios"], default="android", help="Target platform")
    parser.add_argument("--skip", nargs="*", choices=["whatsapp", "sms", "calls", "browser"], default=[], help="Artefacts to skip")
    parser.add_argument("--no-media", action="store_true", help="Skip extract_storage_metadata()")
    parser.add_argument("--dry-run", action="store_true", help="Validate only without acquiring evidence")
    parser.add_argument("--serial", help="Target device serial.")
    parser.add_argument("--version", action="version", version="Antigravity Forensic Acquisition Tool v1.0")
    return parser.parse_args()


def _check_zero_byte(
        file_path: Path,
        artefact_name: str,
        timeline: list,
        add_event,
        fallback_occurred: bool = False) -> None:
    """Forensic guard for checking 0 byte database files."""
    if (file_path.exists() and file_path.stat().st_size == 0) or fallback_occurred:
        alert = f"Forensic Alert: {artefact_name} database physical extraction failed (requires root). "
        if fallback_occurred:
            alert += "Fallback to logical acquisition via Android content providers was activated."
        add_event(alert)


def _init_device(args):
    """Initializes device connection."""
    print("\n[1/5] Initializing Device Connection...")
    manager = AndroidDeviceManager()
    device = manager.connect_device(serial=args.serial)
    if not device:
        print("ERROR: No Android device detected. Check connection.")
        sys.exit(1)
    return device


def _confirm_acquisition(device, args):
    """Prints metadata and confirms acquisition."""
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
    return metadata


def _extract_call_logs(extractor, paths, timeline, add_event):
    """Extracts call logs."""
    add_event("Extracting call log database...")
    call_logs_json = extractor.extract_call_logs()
    fallback_call_logs = False
    if call_logs_json and call_logs_json.exists():
        try:
            with open(call_logs_json, "r") as f:
                data = json.load(f)
                if data and len(data) > 0 and data[0].get("acquisition_method") == "logical_content_provider":
                    fallback_call_logs = True
        except Exception:
            pass
    _check_zero_byte(paths.sub_artefacts["call_log"] / "calllog.db", "Call Log", timeline, add_event, fallback_occurred=fallback_call_logs)
    if getattr(extractor, "call_log_permission_denied", False):
        add_event("Android provider permission denied: READ_CALL_LOG not granted to adb shell context.")


def _extract_sms(extractor, paths, timeline, add_event):
    """Extracts SMS."""
    add_event("Extracting SMS database...")
    sms_json = extractor.extract_sms()
    fallback_sms = False
    if sms_json and sms_json.exists():
        try:
            with open(sms_json, "r") as f:
                data = json.load(f)
                if data and len(data) > 0 and data[0].get("acquisition_method") == "logical_content_provider":
                    fallback_sms = True
        except Exception:
            pass
    _check_zero_byte(paths.sub_artefacts["sms"] / "mmssms.db", "SMS", timeline, add_event, fallback_occurred=fallback_sms)


def _extract_calls_sms(extractor, paths, timeline, add_event, args):
    """Extracts call logs and SMS based on CLI flags."""
    if "calls" not in args.skip:
        _extract_call_logs(extractor, paths, timeline, add_event)
    else:
        add_event("Skipping call logs extraction based on CLI flag.")
    if "sms" not in args.skip:
        _extract_sms(extractor, paths, timeline, add_event)
    else:
        add_event("Skipping SMS extraction based on CLI flag.")


def _extract_browser_whatsapp_media(extractor, paths, timeline, add_event, args):
    """Extracts browser history, WhatsApp, and media metadata based on CLI flags."""
    if "browser" not in args.skip:
        add_event("Extracting Chrome history...")
        extractor.extract_browser_history()
        _check_zero_byte(paths.sub_artefacts["browser_history"] / "Chrome_History", "Browser History", timeline, add_event)
    else:
        add_event("Skipping browser history extraction based on CLI flag.")

    whatsapp_path = None
    if "whatsapp" not in args.skip:
        add_event("Extracting WhatsApp databases...")
        whatsapp_path = extractor.extract_whatsapp()
        if not whatsapp_path:
            add_event("WhatsApp databases inaccessible on non-rooted production emulator.")
    else:
        add_event("Skipping WhatsApp extraction based on CLI flag.")

    if not args.no_media:
        add_event("Mapping external storage metadata...")
        extractor.extract_storage_metadata(filename="storage_manifest.json")
    else:
        add_event("Skipping media metadata extraction based on CLI flag.")
    return whatsapp_path


def _perform_extractions(device, paths, timeline, add_event, args) -> bool:
    """Performs all extraction logic."""
    print("[3/5] Performing Logical Extraction...")
    extractor = DataExtractor(device, paths.artefacts)

    add_event("Extracting installed applications...")
    extractor.extract_apps_to_json(paths.sub_artefacts["installed_apps"] / "apps.json")

    _extract_calls_sms(extractor, paths, timeline, add_event, args)
    whatsapp_path = _extract_browser_whatsapp_media(extractor, paths, timeline, add_event, args)
    return bool(whatsapp_path)


def _verify_integrity(paths, add_event):
    """Hashes artefacts and verifies integrity."""
    print("[4/5] Verifying Data Integrity...")
    hasher = ForensicHasher()
    integrity_manifest = hasher.hash_directory(paths.artefacts)
    hasher.update_manifest(paths.manifest, integrity_manifest)

    report_integrity = [{"filename": k, "hash": v} for k, v in integrity_manifest.items()]
    total_evidence_size = 0
    total_file_count = 0
    for rel_path, expected_hash in integrity_manifest.items():
        artefact_path = paths.artefacts / rel_path
        fsize = artefact_path.stat().st_size if artefact_path.exists() else 0
        total_evidence_size += fsize
        total_file_count += 1
        add_event(f"Artefact extracted: {rel_path} | Size: {fsize} bytes | SHA256: {expected_hash}")
    return report_integrity, total_evidence_size, total_file_count, integrity_manifest


def _load_evidence_summary(paths, whatsapp_accessible: bool):
    """Loads evidence summaries for the report."""
    evidence_summary = {
        "call_logs": [],
        "sms_messages": [],
        "installed_apps": [],
        "browser_history": [],
        "whatsapp_accessible": whatsapp_accessible
    }
    call_log_path = paths.sub_artefacts["call_log"] / "call_logs.json"
    if call_log_path.exists():
        with open(call_log_path, "r") as f:
            evidence_summary["call_logs"] = json.load(f)

    sms_path = paths.sub_artefacts["sms"] / "sms_messages.json"
    if sms_path.exists():
        with open(sms_path, "r") as f:
            evidence_summary["sms_messages"] = json.load(f)

    apps_path = paths.sub_artefacts["installed_apps"] / "apps.json"
    if apps_path.exists():
        with open(apps_path, "r") as f:
            evidence_summary["installed_apps"] = json.load(f)

    browser_path = paths.sub_artefacts["browser_history"] / "browser_history.json"
    if browser_path.exists():
        with open(browser_path, "r") as f:
            evidence_summary["browser_history"] = json.load(f)
    return evidence_summary


def _generate_reports(args, metadata, paths, report_integrity, timeline, start_time, whatsapp_accessible):
    """Generates the final HTML and JSON reports."""
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
    evidence_summary = _load_evidence_summary(paths, whatsapp_accessible)

    reporter.generate_html_report(paths.report_html, case_data, evidence_summary, report_integrity, timeline, artefacts_dir=paths.artefacts)
    reporter.generate_json_report(paths.report_json, case_data, evidence_summary)
    return duration_str


def _final_integrity_check(paths, integrity_manifest, add_event, duration_str, total_file_count, total_evidence_size):
    """Performs final checks and computes acquisition log hash."""
    print("\n[Final] Verifying Final Evidence Integrity...")
    hasher = ForensicHasher()
    verification_success = True
    for rel_path, expected_hash in integrity_manifest.items():
        if hasher.hash_file(paths.artefacts / rel_path) != expected_hash:
            logger = ForensicLogger()
            logger.log_error(f"INTEGRITY FAILURE: {rel_path} has changed!")
            verification_success = False

    if verification_success:
        add_event("Final integrity verification passed.")
    else:
        add_event("CRITICAL: Integrity verification failed.")

    add_event(f"Acquisition Completion: Total duration: {duration_str}, Total files: {total_file_count}, Total evidence size: {total_evidence_size} bytes")
    add_event("Acquisition process completed successfully.")

    log_hash_initial = hasher.hash_file(paths.log_file)
    add_event(f"acquisition.log SHA256 computed: {log_hash_initial}")
    log_hash_final = hasher.hash_file(paths.log_file)
    with open(paths.integrity / "acquisition_hash.txt", "w") as f:
        f.write(f"SHA-256 of acquisition.log: {log_hash_final}\n")
    print("\n--- SUCCESS ---")
    print(f"Report: {paths.report_html.absolute()}")
    print(f"Hashes: {(paths.integrity / 'acquisition_hash.txt').absolute()}")


def _handle_dry_run(args, add_event):
    """Handles the dry run logic and printing planned artefacts."""
    add_event("DRY RUN mode activated. No evidence will be acquired.")
    planned_artefacts = ["installed_apps"]
    if "calls" not in args.skip:
        planned_artefacts.append("call_logs")
    if "sms" not in args.skip:
        planned_artefacts.append("sms_messages")
    if "browser" not in args.skip:
        planned_artefacts.append("browser_history")
    if "whatsapp" not in args.skip:
        planned_artefacts.append("whatsapp")
    if not args.no_media:
        planned_artefacts.append("media_metadata")
    print("\n--- Dry Run Planned Artefacts ---")
    for artefact in planned_artefacts:
        print(f"- {artefact}")


def _setup_logging(paths, logger):
    """Sets up logging and timeline."""
    timeline = []

    def add_event(msg: str):
        """Adds event to timeline."""
        now = datetime.now(timezone.utc)
        ts = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
        timeline.append({"timestamp": ts, "message": msg})
        logger.log_info(msg)
    return timeline, add_event


def _log_startup(add_event, args, metadata, start_time):
    """Logs startup information."""
    add_event(f"Acquisition started for Case: {args.case}")
    add_event("Tool Startup: Antigravity Forensic Acquisition Tool v1.0")
    add_event(f"CLI Arguments: case={args.case}, investigator={args.investigator}, serial={args.serial}, dry_run={args.dry_run}, platform={args.platform}, skip={args.skip}, no_media={args.no_media}")
    add_event(f"Device Connection: Model={metadata.get('model')}, Serial={metadata.get('serial_number')}, Android Version={metadata.get('android_version')}")
    add_event(f"Investigator confirmation: Investigator {args.investigator} authorized acquisition.")


def main() -> None:
    """Main orchestration for forensic acquisition."""
    args = setup_argparse()

    if args.platform == "ios":
        paths = EvidenceManager.create_structure(args.output, "ios_device")
        logger = ForensicLogger()
        logger.set_log_file(paths.log_file)
        print("iOS acquisition not implemented")
        logger.log_info("iOS acquisition not implemented. Exiting safely.")
        sys.exit(0)

    device = _init_device(args)
    metadata = _confirm_acquisition(device, args)

    drift_ms = device.calculate_clock_drift()
    if drift_ms is not None:
        print(f"[*] Clock Drift: {drift_ms:+.3f}ms (logged to acquisition.log)")

    print("\n[2/5] Creating Evidence Structure...")
    paths = EvidenceManager.create_structure(args.output, device.serial)
    logger = ForensicLogger()
    logger.set_log_file(paths.log_file)
    timeline, add_event = _setup_logging(paths, logger)

    start_time = datetime.now(timezone.utc)
    _log_startup(add_event, args, metadata, start_time)

    if args.dry_run:
        _handle_dry_run(args, add_event)
        return print("\nDRY RUN complete. Device is reachable.")

    whatsapp_accessible = _perform_extractions(device, paths, timeline, add_event, args)
    report_integrity, total_evidence_size, total_file_count, integrity_manifest = _verify_integrity(paths, add_event)
    duration_str = _generate_reports(args, metadata, paths, report_integrity, timeline, start_time, whatsapp_accessible)
    _final_integrity_check(paths, integrity_manifest, add_event, duration_str, total_file_count, total_evidence_size)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAcquisition interrupted by user.")
    except Exception as e:
        print(f"\nCRITICAL ERROR: {e}")
