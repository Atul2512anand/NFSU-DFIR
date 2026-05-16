"""
Module for forensic acquisition.
"""

import json
from pathlib import Path
from typing import Dict
import hashlib
from .logger import ForensicLogger

# Initialize logger for this module
logger = ForensicLogger()


class ForensicHasher:
    """
    Handles cryptographic hashing and manifest management for evidence.
    Handles cryptographic hashing and manifest management for evidence.
    Uses built-in hashlib for SHA-256 calculations.
    """

    def __init__(self, block_size: int = 65536):
        """
        Args:
            block_size (int): Size of the buffer for reading large files.
        """
        self.block_size = block_size

    def hash_file(self, file_path: Path) -> str:
        """
        Calculates the SHA-256 hex digest for a single file.

        Returns:
            str: Hexadecimal digest of the file hash.
        """
        if not file_path.exists() or not file_path.is_file():
            logger.log_error(
                f"Cannot hash missing or invalid file: {file_path}"
            )
            return ""

        hasher = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(self.block_size):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.log_error(f"Error hashing file {file_path}: {e}")
            return ""

    def hash_directory(self, dir_path: Path) -> Dict[str, str]:
        """
        Calculates hashes for all files within a directory (recursive).

        Returns:
            Dict[str, str]: Mapping of relative file paths to their hex digests.
        """
        results = {}
        if not dir_path.exists() or not dir_path.is_dir():
            return results

        for file in dir_path.rglob("*"):
            if file.is_file():
                relative_path = str(file.relative_to(dir_path))
                results[relative_path] = self.hash_file(file)

        return results

    def update_manifest(self, manifest_path: Path,
                        new_hashes: Dict[str, str]) -> bool:
        """
        Updates or creates a JSON manifest file with new hash entries.

        Args:
            manifest_path (Path): Path to the manifest.json file.
            new_hashes (Dict[str, str]): Dictionary of file paths and hashes to add.
        """
        manifest_data = {}

        try:
            if manifest_path.exists():
                with open(manifest_path, "r") as f:
                    manifest_data = json.load(f)

            manifest_data.update(new_hashes)

            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            with open(manifest_path, "w") as f:
                json.dump(manifest_data, f, indent=4)

            logger.log_info(f"Integrity manifest updated at: {manifest_path}")
            return True
        except Exception as e:
            logger.log_error(f"Failed to update manifest: {e}")
            return False
