"""
Module for forensic acquisition.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from jinja2 import Environment, FileSystemLoader
from .logger import ForensicLogger

logger = ForensicLogger()


def _format_date(dt_val: Any) -> str:
    """Formats datetime safely."""
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


class ForensicReporter:
    """Generates comprehensive forensic reports in HTML and JSON formats."""

    def __init__(self, template_dir: Path):
        """Function documentation."""
        self.template_dir = template_dir
        self.env = Environment(loader=FileSystemLoader(str(template_dir)))

    def _check_root_flags(self, evidence: dict, artefacts_dir: Path):
        """Injects root required flags for empty databases."""
        _zero_byte_checks = [
            (artefacts_dir / "call_log" / "calllog.db", "call_logs_root_required"),
            (artefacts_dir / "sms" / "mmssms.db", "sms_root_required"),
            (artefacts_dir / "browser_history" / "Chrome_History", "browser_root_required"),
        ]
        for db_path, flag_key in _zero_byte_checks:
            if db_path.exists() and db_path.stat().st_size == 0:
                evidence[flag_key] = True

    def _build_timeline(self, evidence: dict) -> List[dict]:
        """Builds unified timeline from all evidence types."""
        events = []
        for msg in evidence.get("sms_messages", []):
            events.append({
                "timestamp": _format_date(msg.get("date")),
                "category": "SMS",
                "summary": f"Message received from {msg.get('address', 'Unknown')}",
                "method": msg.get("acquisition_method", "physical_sqlite")
            })
        for call in evidence.get("call_logs", []):
            direction = "Outgoing" if str(call.get("type")) == "2" else "Incoming"
            events.append({
                "timestamp": _format_date(call.get("date")),
                "category": "CALL",
                "summary": f"{direction} call to {call.get('number', 'Unknown')}",
                "method": call.get("acquisition_method", "physical_sqlite")
            })
        for app in evidence.get("installed_apps", []):
            events.append({
                "timestamp": _format_date(app.get("install_date")),
                "category": "APP",
                "summary": f"Installed {app.get('package_name', 'Unknown')}",
                "method": "dumpsys_api"
            })
        for visit in evidence.get("browser_history", []):
            events.append({
                "timestamp": _format_date(visit.get("last_visit")),
                "category": "BROWSER",
                "summary": f"Chrome history record: {visit.get('url', 'Unknown')}",
                "method": visit.get("acquisition_method", "physical_sqlite")
            })
        events.sort(key=lambda x: x["timestamp"])
        return events

    def generate_html_report(self,
                             output_path: Path,
                             case_info: Dict[str, Any],
                             evidence: Dict[str, List[Dict[str, Any]]],
                             integrity_data: List[Dict[str, str]],
                             timeline: List[Dict[str, str]],
                             artefacts_dir: Optional[Path] = None) -> Path:
        """Renders the evidence data into a responsive HTML report."""
        try:
            logger.log_info(f"Generating HTML report at {output_path}...")
            template = self.env.get_template("report.html.j2")
            now_utc = datetime.now(timezone.utc)
            case_info["report_date"] = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

            if artefacts_dir is not None:
                self._check_root_flags(evidence, artefacts_dir)

            unified_timeline_events = self._build_timeline(evidence)

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
        """Exports the acquisition metadata and evidence records to JSON."""
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
