import logging
import os
import pytest
from pathlib import Path
from src.logger import ForensicLogger


@pytest.fixture(autouse=True)
def reset_logger():
    """Resets the global logger handlers between tests to prevent interference."""
    logger = logging.getLogger("ForensicAcquisition")
    logger.handlers.clear()
    yield
    logger.handlers.clear()


@pytest.fixture
def log_file(tmp_path):
    """Provides a path for a temporary log file."""
    return tmp_path / "test_acquisition.log"


def test_logger_file_creation(log_file):
    """Verifies that the logger correctly creates the log file."""
    logger = ForensicLogger()
    logger.set_log_file(log_file)

    logger.log_info("Test log entry")

    assert log_file.exists()
    content = log_file.read_text()
    assert "Test log entry" in content
    assert "INFO" in content


def test_utc_timestamp_format(log_file):
    """Verifies that the log entries use the correct forensic UTC format (Z suffix)."""
    logger = ForensicLogger()
    logger.set_log_file(log_file)

    logger.log_info("Timestamp check")

    content = log_file.read_text()
    # Looking for format like 2024-05-08T12:00:00.000Z
    import re
    assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", content)


def test_logger_error_level(log_file):
    """Verifies that error level logs are correctly recorded."""
    logger = ForensicLogger()
    logger.set_log_file(log_file)

    logger.log_error("Critical failure")

    content = log_file.read_text()
    assert "[ERROR]" in content
    assert "Critical failure" in content
