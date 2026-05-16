"""
Module for forensic acquisition.
"""

import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import Dict


@dataclass
class EvidencePaths:
    """Holds the generated paths for the forensic evidence structure."""
    root: Path
    artefacts: Path
    integrity: Path
    log_file: Path
    manifest: Path
    device_info: Path
    report_html: Path
    report_json: Path
    sub_artefacts: Dict[str, Path]


class EvidenceManager:
    """
    Manages the creation and organization of the forensic output directory.
    Ensures unique, timestamped directories for each acquisition.
    """

    @staticmethod
    def _get_root_path(base_dir: Path, serial: str) -> Path:
        """Generates a unique root directory path for the acquisition."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        root_name = f"evidence_{serial}_{timestamp}"
        root_path = base_dir / root_name
        counter = 1
        while root_path.exists():
            root_path = base_dir / f"{root_name}_{counter}"
            counter += 1
        return root_path

    @staticmethod
    def _create_sub_dirs(artefacts_path: Path) -> Dict[str, Path]:
        """Creates and returns the sub-artefact directories."""
        sub_dirs = [
            "call_log", "sms", "browser_history",
            "installed_apps", "whatsapp", "media_metadata"
        ]
        sub_artefact_paths = {}
        for sub in sub_dirs:
            path = artefacts_path / sub
            path.mkdir(parents=True, exist_ok=True)
            sub_artefact_paths[sub] = path
        return sub_artefact_paths

    @staticmethod
    def create_structure(base_dir: Path, serial: str) -> EvidencePaths:
        """
        Creates the directory structure for a new forensic acquisition.
        """
        root_path = EvidenceManager._get_root_path(base_dir, serial)
        artefacts_path = root_path / "artefacts"
        integrity_path = root_path / "integrity"

        sub_paths = EvidenceManager._create_sub_dirs(artefacts_path)
        integrity_path.mkdir(parents=True, exist_ok=True)

        return EvidencePaths(
            root=root_path,
            artefacts=artefacts_path,
            integrity=integrity_path,
            log_file=root_path / "acquisition.log",
            manifest=root_path / "manifest.json",
            device_info=root_path / "device_info.json",
            report_html=root_path / "report.html",
            report_json=root_path / "report.json",
            sub_artefacts=sub_paths
        )
