import os
import json
import pytest
import re
from pathlib import Path
from src.hasher import ForensicHasher
from src.logger import ForensicLogger


def test_sha256_correctness(tmp_path):
    hasher = ForensicHasher()
    test_file = tmp_path / "test.txt"
    test_file.write_bytes(b"forensics")
    expected_hash = "b83d7514ba17c3f1156a2648c1a9d3d167143e695ad491e6197f88441c7a1e4a"
    actual_hash = hasher.hash_file(test_file)
    assert actual_hash == expected_hash


def test_manifest_integrity_structure(tmp_path):
    hasher = ForensicHasher()
    f1 = tmp_path / "f1.txt"
    f1.write_text("data1")
    f2 = tmp_path / "f2.txt"
    f2.write_text("data2")

    # Pre-hash to add to internal state
    manifest_path = tmp_path / "manifest.json"
    hashes = {
        "f1.txt": hasher.hash_file(f1),
        "f2.txt": hasher.hash_file(f2)
    }
    hasher.update_manifest(manifest_path, hashes)

    assert manifest_path.exists()
    with open(manifest_path, "r") as f:
        data = json.load(f)

    assert "f1.txt" in data
    assert "f2.txt" in data
    assert len(data.keys()) >= 2


def test_logging_entry_format_validation(tmp_path):
    log_file = tmp_path / "acquisition.log"
    logger = ForensicLogger()
    logger.set_log_file(log_file)

    logger.log_info("Test info message")
    logger.log_error("Test error message")
    logger.log_warning("Test warning message")

    with open(log_file, "r") as f:
        content = f.read()

    lines = content.strip().split("\n")
    assert len(lines) == 3
    assert "[INFO] Test info message" in lines[0]
    assert "[ERROR] Test error message" in lines[1]
    assert "[WARNING] Test warning message" in lines[2]


def test_utc_timestamp_formatting(tmp_path):
    log_file = tmp_path / "acquisition2.log"
    logger = ForensicLogger()
    import logging
    for h in logger.logger.handlers[:]:
        if isinstance(h, logging.FileHandler):
            logger.logger.removeHandler(h)
    logger.set_log_file(log_file)
    logger.log_info("Timestamp check")

    with open(log_file, "r") as f:
        content = f.read().strip()

    # Expected format: 2026-05-16T08:16:34.123Z [INFO] Timestamp check
    # Regex matching ISO 8601 UTC with milliseconds and Z
    pattern = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z \[INFO\] Timestamp check$"
    assert re.match(pattern, content) is not None


def test_inaccessible_artefact_hash_handling(tmp_path):
    hasher = ForensicHasher()
    # Hashing a non-existent file should gracefully return ""
    missing_file = tmp_path / "does_not_exist.txt"
    hash_val = hasher.hash_file(missing_file)
    assert hash_val == ""
