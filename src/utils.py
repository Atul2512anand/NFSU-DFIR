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
    def create_structure(base_dir: Path, serial: str) -> EvidencePaths:
        """
        Creates the directory structure for a new forensic acquisition.

        Args:
            base_dir (Path): Parent directory where evidence will be stored.
            serial (str): The serial number of the target device.

        Returns:
            EvidencePaths: Object containing all created directory/file paths.
        """
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        root_name = f"evidence_{serial}_{timestamp}"
        root_path = base_dir / root_name

        # Ensure we don't overwrite (unlikely with timestamp)
        counter = 1
        while root_path.exists():
            root_path = base_dir / f"{root_name}_{counter}"
            counter += 1

        # Create main directories
        artefacts_path = root_path / "artefacts"
        integrity_path = root_path / "integrity"

        # Define sub-artefacts
        sub_dirs = [
            "call_log", "sms", "browser_history",
            "installed_apps", "whatsapp", "media_metadata"
        ]

        sub_artefact_paths = {}
        for sub in sub_dirs:
            path = artefacts_path / sub
            path.mkdir(parents=True, exist_ok=True)
            sub_artefact_paths[sub] = path

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
            sub_artefacts=sub_artefact_paths
        )
