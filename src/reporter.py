"""
Module for forensic acquisition.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from jinja2 import Environment, FileSystemLoader
from .logger import ForensicLogger

# Initialize logger for this module
logger = ForensicLogger()


class ForensicReporter:
    """
    Generates comprehensive forensic reports in HTML and JSON formats.
    Uses Jinja2 for responsive and professional HTML rendering.
    """

    def __init__(self, template_dir: Path):
        """
        Args:
            template_dir (Path): Directory containing the Jinja2 templates.
        """
        self.template_dir = template_dir
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))

    def generate_html_report(self,
                             output_path: Path,
                             case_info: Dict[str, Any],
                             evidence: Dict[str, List[Dict[str, Any]]],
                             integrity_data: List[Dict[str, str]],
                             timeline: List[Dict[str, str]],
                             artefacts_dir: Optional[Path] = None) -> Path:
        """
        Renders the evidence data into a responsive HTML report.
        If artefacts_dir is provided, checks for 0-byte database files and
        injects root_required flags so the template can show appropriate banners.
        """
        try:
            logger.log_info(f"Generating HTML report at {output_path}...")
            template = self.env.get_template("report.html.j2")

            # Ensure report date is set to now in UTC
            now_utc = datetime.now(timezone.utc)
            case_info["report_date"] = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

            # --- Forensic Root-Required Detection ---
            # If a pulled database is 0 bytes, ADB was blocked by permissions.
            # Inject a flag so the template can display "Data Unavailable (Root
            # Required)".
            if artefacts_dir is not None:
                _zero_byte_checks = [
                    (artefacts_dir / "contacts2.db", "call_logs_root_required"),
                    (artefacts_dir / "mmssms.db", "sms_root_required"),
                    (artefacts_dir / "Chrome_History", "browser_root_required"),
                ]
                for db_path, flag_key in _zero_byte_checks:
                    if db_path.exists() and db_path.stat().st_size == 0:
                        evidence[flag_key] = True

            def format_date(dt_val: Any) -> str:
                """Function documentation."""

                s = str(dt_val).strip()
                if not s or s == "None":
                    return "1970-01-01T00:00:00Z"
                if s.isdigit():
                    try:
                        return datetime.fromtimestamp(
                            int(s) / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    except Exception:
                        return s
                if " " in s and not s.endswith("Z"):
                    return s.replace(" ", "T") + "Z"
                return s

            unified_timeline_events = []

            for msg in evidence.get("sms_messages", []):
                unified_timeline_events.append({
                    "timestamp": format_date(msg.get("date")),
                    "category": "SMS",
                    "summary": f"Message received from {msg.get('address', 'Unknown')}",
                    "method": msg.get("acquisition_method", "physical_sqlite")
                })

            for call in evidence.get("call_logs", []):
                direction = "Outgoing" if str(
                    call.get("type")) == "2" else "Incoming"
                unified_timeline_events.append({
                    "timestamp": format_date(call.get("date")),
                    "category": "CALL",
                    "summary": f"{direction} call to {call.get('number', 'Unknown')}",
                    "method": call.get("acquisition_method", "physical_sqlite")
                })

            for app in evidence.get("installed_apps", []):
                unified_timeline_events.append({
                    "timestamp": format_date(app.get("install_date")),
                    "category": "APP",
                    "summary": f"Installed {app.get('package_name', 'Unknown')}",
                    "method": "dumpsys_api"
                })

            for visit in evidence.get("browser_history", []):
                unified_timeline_events.append({
                    "timestamp": format_date(visit.get("last_visit")),
                    "category": "BROWSER",
                    "summary": f"Chrome history record: {visit.get('url', 'Unknown')}",
                    "method": visit.get("acquisition_method", "physical_sqlite")
                })

            unified_timeline_events.sort(key=lambda x: x["timestamp"])

            html_content = template.render(
                case_info=case_info,
                evidence=evidence,
                integrity_data=integrity_data,
                timeline=timeline,
                unified_timeline=unified_timeline_events
            )

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

            logger.log_info("HTML report generated successfully.")
            return output_path
        except Exception as e:
            logger.log_error(f"Failed to generate HTML report: {e}")
            return output_path

    def generate_json_report(self,
                             output_path: Path,
                             case_info: Dict[str, Any],
                             evidence: Dict[str, List[Dict[str, Any]]]
                             ) -> Path:
        """
        Exports the acquisition metadata and evidence records to a
        machine-readable JSON format.
        """
        report_data = {
            "metadata": case_info,
            "report_generated_at": datetime.now(timezone.utc).isoformat(),
            "evidence": evidence
        }

        try:
            logger.log_info(f"Generating JSON report at {output_path}...")
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=4)

            logger.log_info("JSON report generated successfully.")
            return output_path
        except Exception as e:
            logger.log_error(f"Failed to generate JSON report: {e}")
            return output_path
