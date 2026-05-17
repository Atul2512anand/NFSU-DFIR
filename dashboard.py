"""
NFSU Forensic Acquisition Dashboard — Flask Backend
Run with: python dashboard.py
Then open: http://localhost:5000
"""
import json
import queue
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request

# ── Project imports ──────────────────────────────────────────────────────────
from src.device import AndroidDeviceManager
from src.extractor import DataExtractor
from src.hasher import ForensicHasher
from src.logger import ForensicLogger
from src.reporter import ForensicReporter
from src.utils import EvidenceManager

app = Flask(__name__, template_folder="templates")

# Global state shared between threads
_sessions: dict = {}          # session_id -> dict of results / queue / status
_logger = ForensicLogger()


# ── Helpers ──────────────────────────────────────────────────────────────────

def _now_ms() -> str:
    """Millisecond-accurate UTC timestamp string."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"


def _emit(q: queue.Queue, event: str, data: dict) -> None:
    """Push an SSE event onto the session queue."""
    q.put({"event": event, "data": data})


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


def _get_battery_level(shell):
    try:
        for line in shell("dumpsys battery", "").splitlines():
            if "level:" in line.lower():
                return "".join(filter(str.isdigit, line.split(":")[1]))
    except Exception:
        pass
    return "N/A"


def _get_storage_info(shell):
    try:
        parts = shell("df /data 2>/dev/null | tail -1", "").split()
        if len(parts) >= 4:
            total_kb, used_kb, free_kb = int(parts[1]), int(parts[2]), int(parts[3])
            return {
                "total_gb": round(total_kb / 1024 / 1024, 2),
                "used_gb":  round(used_kb / 1024 / 1024, 2),
                "free_gb":  round(free_kb / 1024 / 1024, 2),
                "used_pct": round(used_kb / total_kb * 100, 1) if total_kb else 0
            }
    except Exception:
        pass
    return {}


def _get_extra_device_info(shell, meta, drift_ms):
    uptime_raw = shell("cat /proc/uptime")
    uptime_secs = int(float(uptime_raw.split()[0])) if uptime_raw != "N/A" else 0
    uptime_str = f"{uptime_secs // 3600}h {(uptime_secs % 3600) // 60}m"
    ip_addr = shell("ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \\K\\S+'")
    if not ip_addr or ip_addr == "N/A":
        ip_addr = shell("ip addr show wlan0 2>/dev/null | grep -oP '(?<=inet )\\S+' | cut -d/ -f1")
    app_count_raw = shell("pm list packages | wc -l")
    try:
        app_count = int(app_count_raw)
    except Exception:
        app_count = "N/A"

    return {
        "serial":           meta.get("serial_number", "N/A"),
        "model":            meta.get("model", "N/A"),
        "manufacturer":     meta.get("manufacturer", "N/A"),
        "brand":            shell("getprop ro.product.brand"),
        "device_name":      shell("getprop ro.product.device"),
        "android_version":  meta.get("android_version", "N/A"),
        "sdk_version":      shell("getprop ro.build.version.sdk"),
        "security_patch":   shell("getprop ro.build.version.security_patch"),
        "cpu_abi":          shell("getprop ro.product.cpu.abi"),
        "kernel":           shell("uname -r"),
        "device_time":      meta.get("device_time", "N/A"),
        "battery":          _get_battery_level(shell),
        "clock_drift_ms":   round(drift_ms, 3) if drift_ms is not None else None,
        "ip_address":       ip_addr,
        "build_fingerprint": shell("getprop ro.build.fingerprint"),
        "storage":          _get_storage_info(shell),
        "app_count":        app_count,
        "uptime":           uptime_str,
    }


@app.route("/api/scan", methods=["POST"])
def scan_device():
    """Scan for a connected USB Android device."""
    try:
        manager = AndroidDeviceManager()
        device = manager.connect_device(auth_timeout_s=5)
        if not device:
            return jsonify({
                "success": False,
                "error": "No device detected. Plug in phone and enable USB Debugging."
            })

        meta = device.fetch_metadata()
        drift_ms = device.calculate_clock_drift()

        def shell(cmd, default="N/A"):
            try:
                return device.adb.shell(cmd).strip() or default
            except Exception:
                return default

        device_info = _get_extra_device_info(shell, meta, drift_ms)
        device.adb.close()

        return jsonify({
            "success": True,
            "device": device_info
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/acquire", methods=["POST"])
def start_acquisition():
    """
    Start a full forensic acquisition in a background thread.
    Returns a session_id to poll via SSE.
    """
    body = request.get_json(silent=True) or {}
    case_id = body.get("case_id", "NFSU-CASE-001")
    investigator = body.get("investigator", "Investigator")
    output_dir = Path("./output")

    session_id = f"acq_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    q: queue.Queue = queue.Queue()

    _sessions[session_id] = {
        "queue":    q,
        "status":   "running",
        "results":  {},
        "timeline": [],
    }

    def run_acquisition():
        sess = _sessions[session_id]
        timeline = sess["timeline"]

        def add_event(msg: str, level: str = "info"):
            ts = _now_ms()
            entry = {"timestamp": ts, "message": msg, "level": level}
            timeline.append(entry)
            _emit(q, "timeline", entry)

        def step1_connect():
            _emit(q, "progress", {"step": 1, "label": "Connecting to device..."})
            manager = AndroidDeviceManager()
            device = manager.connect_device(auth_timeout_s=30)
            if not device:
                _emit(q, "error", {"message": "No device found. Plug in phone and ensure USB Debugging is ON."})
                sess["status"] = "error"
                return None, None
            meta = device.fetch_metadata()
            drift_ms = device.calculate_clock_drift()
            try:
                battery_raw = device.adb.shell("dumpsys battery")
                battery_level = "N/A"
                for line in battery_raw.splitlines():
                    if "level:" in line.lower():
                        parts = line.split(":")
                        if len(parts) > 1:
                            battery_level = "".join(filter(str.isdigit, parts[1]))
                            break
            except Exception:
                battery_level = "N/A"
            device_info = {
                **meta,
                "battery": battery_level,
                "clock_drift_ms": round(drift_ms, 3) if drift_ms is not None else None,
            }
            sess["results"]["device_info"] = device_info
            _emit(q, "device_info", device_info)
            add_event(f"Connected to {meta.get('model')} [{meta.get('serial_number')}]")
            add_event(f"Clock drift: {drift_ms:+.3f}ms" if drift_ms is not None else "Clock drift: N/A")
            return device, meta

        def step2_extract_apps(device):
            _emit(q, "progress", {"step": 2, "label": "Creating evidence structure..."})
            paths = EvidenceManager.create_structure(output_dir, device.serial)
            _logger.set_log_file(paths.log_file)
            add_event(f"Evidence folder: {paths.root}")
            extractor = DataExtractor(device, paths.artefacts)
            _emit(q, "progress", {"step": 3, "label": "Extracting installed apps..."})
            add_event("Extracting installed applications...")
            extractor.extract_apps_to_json(paths.sub_artefacts["installed_apps"] / "apps.json")
            apps_path = paths.sub_artefacts["installed_apps"] / "apps.json"
            apps = []
            if apps_path.exists():
                with open(apps_path, "r") as f:
                    apps = json.load(f)
            sess["results"]["installed_apps"] = apps
            _emit(q, "installed_apps", {"count": len(apps), "apps": apps[:200]})
            add_event(f"Found {len(apps)} installed applications")
            return extractor, paths, apps

        def step3_extract_comms(extractor, paths):
            _emit(q, "progress", {"step": 4, "label": "Extracting call logs..."})
            add_event("Extracting call log database...")
            extractor.extract_call_logs()
            call_db = paths.sub_artefacts["call_log"] / "calllog.db"
            call_json = paths.sub_artefacts["call_log"] / "call_logs.json"
            calls = []
            call_root_required = False
            if call_db.exists() and call_db.stat().st_size == 0:
                call_root_required = True
                add_event("Forensic Alert: Call Log database is empty — Root Required", "warning")
            elif call_json.exists():
                with open(call_json, "r") as f:
                    calls = json.load(f)
            sess["results"]["call_logs"] = calls
            sess["results"]["call_logs_root_required"] = call_root_required
            _emit(q, "call_logs", {"root_required": call_root_required, "count": len(calls), "calls": calls})
            add_event(
                f"Call logs: {len(calls)} records extracted" if not call_root_required else "Call logs: Root Required")

            _emit(q, "progress", {"step": 5, "label": "Extracting SMS messages..."})
            add_event("Extracting SMS database...")
            extractor.extract_sms()
            sms_db = paths.sub_artefacts["sms"] / "mmssms.db"
            sms_json = paths.sub_artefacts["sms"] / "sms_messages.json"
            sms_msgs = []
            sms_root_required = False
            if sms_db.exists() and sms_db.stat().st_size == 0:
                sms_root_required = True
                add_event("Forensic Alert: SMS database is empty — Root Required", "warning")
            elif sms_json.exists():
                with open(sms_json, "r") as f:
                    sms_msgs = json.load(f)
            sess["results"]["sms_messages"] = sms_msgs
            sess["results"]["sms_root_required"] = sms_root_required
            _emit(q, "sms_messages", {"root_required": sms_root_required, "count": len(sms_msgs), "messages": sms_msgs})
            add_event(f"SMS: {len(sms_msgs)} messages extracted" if not sms_root_required else "SMS: Root Required")
            return calls, sms_msgs

        def step4_extract_browser_storage(extractor, paths):
            _emit(q, "progress", {"step": 6, "label": "Extracting browser history..."})
            add_event("Extracting Chrome browser history...")
            extractor.extract_browser_history()
            brow_db = paths.sub_artefacts["browser_history"] / "Chrome_History"
            brow_json = paths.sub_artefacts["browser_history"] / "browser_history.json"
            history = []
            brow_root_required = False
            if brow_db.exists() and brow_db.stat().st_size == 0:
                brow_root_required = True
                add_event("Forensic Alert: Browser History is empty — Root Required", "warning")
            elif brow_json.exists():
                with open(brow_json, "r") as f:
                    history = json.load(f)
            sess["results"]["browser_history"] = history
            sess["results"]["browser_root_required"] = brow_root_required
            _emit(q, "browser_history", {"root_required": brow_root_required,
                  "count": len(history), "history": history})
            add_event(
                f"Browser history: {len(history)} URLs extracted" if not brow_root_required else "Browser history: Root Required")

            _emit(q, "progress", {"step": 7, "label": "Mapping external storage..."})
            add_event("Scanning /sdcard/ storage metadata...")
            extractor.extract_storage_metadata(filename="storage_manifest.json")

            # --- BONUS FEATURES ---
            _emit(q, "progress", {"step": 7, "label": "Extracting EXIF GPS..."})
            add_event("Extracting EXIF metadata from images...")
            extractor.extract_exif_gps()
            exif_path = paths.sub_artefacts["media_metadata"] / "exif_locations.json"
            exif_data = []
            if exif_path.exists():
                with open(exif_path, "r", encoding="utf-8") as f:
                    exif_data = json.load(f)
            sess["results"]["exif_data"] = exif_data
            _emit(q, "exif_data", {"count": len(exif_data), "data": exif_data})

            _emit(q, "progress", {"step": 7, "label": "Analyzing deleted records..."})
            add_event("Inspecting SQLite freelist pages...")
            extractor.extract_deleted_records_stats()
            deleted_path = paths.artefacts / "deleted_record_analysis.json"
            deleted_stats = []
            if deleted_path.exists():
                with open(deleted_path, "r", encoding="utf-8") as f:
                    deleted_stats = json.load(f)
            sess["results"]["deleted_stats"] = deleted_stats
            _emit(q, "deleted_stats", {"count": len(deleted_stats), "data": deleted_stats})
            # ----------------------

            stor_path = paths.sub_artefacts["media_metadata"] / "storage_manifest.json"
            storage_files = []
            if stor_path.exists():
                with open(stor_path, "r") as f:
                    storage_files = json.load(f)
            sess["results"]["storage_files"] = storage_files
            _emit(q, "storage_files", {"count": len(storage_files), "files": storage_files[:500]})
            add_event(f"Storage map: {len(storage_files)} files indexed")
            return history, storage_files

        def step5_integrity_report(paths, meta, apps, calls, sms_msgs, history, storage_files):
            _emit(q, "progress", {"step": 8, "label": "Computing integrity hashes..."})
            add_event("Computing SHA-256 integrity hashes...")
            hasher = ForensicHasher()
            manifest = hasher.hash_directory(paths.artefacts)
            hasher.update_manifest(paths.manifest, manifest)
            integrity_list = [{"filename": k, "hash": v} for k, v in manifest.items()]
            sess["results"]["integrity"] = integrity_list
            _emit(q, "integrity", {"hashes": integrity_list})
            add_event(f"Integrity manifest complete: {len(integrity_list)} files hashed")

            _emit(q, "progress", {"step": 9, "label": "Generating forensic report..."})
            add_event("Generating HTML forensic report...")
            reporter = ForensicReporter(template_dir=Path("./templates"))

            case_data = {
                "case_id":        case_id,
                "investigator":   investigator,
                "device_serial":  meta.get("serial_number"),
                "device_model":   meta.get("model"),
                "android_version": meta.get("android_version"),
            }

            # --- BONUS: LOAD EXIF & DELETED STATS ---
            exif_data = []
            exif_path = paths.sub_artefacts["media_metadata"] / "exif_locations.json"
            if exif_path.exists():
                with open(exif_path, "r", encoding="utf-8") as f:
                    exif_data = json.load(f)

            deleted_stats = []
            deleted_path = paths.artefacts / "deleted_record_analysis.json"
            if deleted_path.exists():
                with open(deleted_path, "r", encoding="utf-8") as f:
                    deleted_stats = json.load(f)
            # ----------------------------------------

            evidence_summary = {
                "call_logs":      calls,
                "sms_messages":   sms_msgs,
                "browser_history": history,
                "installed_apps": apps,
                "storage_files":  storage_files,
                "timeline":       timeline,
                "exif_locations": exif_data,
                "deleted_record_analysis": deleted_stats,
            }

            reporter.generate_html_report(
                paths.report_html, case_data, evidence_summary,
                integrity_list, timeline, artefacts_dir=paths.artefacts
            )
            add_event(f"HTML report saved to {paths.report_html.name}")

        try:
            device, meta = step1_connect()
            if not device:
                return
            extractor, paths, apps = step2_extract_apps(device)
            calls, sms_msgs = step3_extract_comms(extractor, paths)
            history, storage_files = step4_extract_browser_storage(extractor, paths)
            step5_integrity_report(paths, meta, apps, calls, sms_msgs, history, storage_files)

            _emit(q, "progress", {"step": 10, "label": "Acquisition Complete"})
            sess["status"] = "complete"
            sess["results"]["report_url"] = f"/report/{session_id}"
            _emit(q, "complete", {"report_url": sess["results"]["report_url"]})
            add_event("Acquisition process completed successfully.")

        except Exception as e:
            _emit(q, "error", {"message": f"Acquisition failed: {str(e)}"})
            sess["status"] = "error"
            add_event(f"Critical error: {str(e)}", "error")
    threading.Thread(
        target=run_acquisition,
        daemon=True
    ).start()

    return jsonify({
        "success": True,
        "session_id": session_id,
        "message": "Acquisition started successfully"
    })


@app.route("/api/stream/<session_id>")
def stream(session_id):
    """
    Server-Sent Events stream for live acquisition updates.
    """

    if session_id not in _sessions:
        return jsonify({
            "success": False,
            "error": "Invalid session ID"
        }), 404

    q = _sessions[session_id]["queue"]

    def event_stream():
        while True:
            try:
                item = q.get(timeout=1)

                yield (
                    f"event: {item['event']}\n"
                    f"data: {json.dumps(item['data'])}\n\n"
                )

                if item["event"] == "complete":
                    break

            except queue.Empty:
                continue

            except GeneratorExit:
                break

    return Response(
        event_stream(),
        mimetype="text/event-stream"
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
