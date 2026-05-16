import os
import pytest
from pathlib import Path
from src.reporter import ForensicReporter


@pytest.fixture
def dummy_evidence():
    return {"sms_messages": [{"address": "+12345",
                              "body": "test sms",
                              "date": 1628701402000,
                              "acquisition_method": "logical"}],
            "call_logs": [{"number": "98765",
                           "duration": 45,
                           "type": 2,
                           "date": 1628701402000,
                           "name": "Test",
                           "acquisition_method": "physical"}],
            "installed_apps": [{"package_name": "com.test.app",
                                "version": "1.0",
                                "install_date": "2023-01-01 12:00:00"}],
            "browser_history": [],
            "whatsapp_accessible": False}


@pytest.fixture
def dummy_case_info():
    return {
        "case_id": "TEST-001",
        "investigator": "Test Inv",
        "device_serial": "SERIAL123",
        "device_model": "Test Model",
        "android_version": "13",
        "start_time": "2026-01-01T00:00:00Z",
        "end_time": "2026-01-01T00:01:00Z",
        "duration": "00:01:00"
    }


@pytest.fixture
def dummy_integrity():
    return [{"filename": "contacts2.db",
             "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            {"filename": "mmssms.db",
             "hash": "abcdef123456"}]


@pytest.fixture
def dummy_timeline():
    return [{"timestamp": "2026-01-01T00:00:00.000Z",
             "message": "Started test acquisition"}]


def test_report_html_generation(
        tmp_path,
        dummy_evidence,
        dummy_case_info,
        dummy_integrity,
        dummy_timeline):
    template_dir = Path("templates")
    reporter = ForensicReporter(template_dir)
    output_html = tmp_path / "report.html"

    reporter.generate_html_report(
        output_path=output_html,
        case_info=dummy_case_info,
        evidence=dummy_evidence,
        integrity_data=dummy_integrity,
        timeline=dummy_timeline
    )

    assert output_html.exists()
    content = output_html.read_text(encoding="utf-8")

    # Check sections exist
    assert "Acquisition Summary" in content
    assert "Acquisition Timeline" in content
    assert "Unified Forensic Timeline" in content

    # Check data rendering
    assert "TEST-001" in content
    assert "SERIAL123" in content
    assert "+12345" in content
    assert "98765" in content
    assert "com.test.app" in content

    # Empty hash translates to warning badge
    assert "Acquisition Attempted — Data Inaccessible" in content
    assert "abcdef123456" in content


def test_generate_json_report(tmp_path, dummy_evidence, dummy_case_info):
    template_dir = Path("templates")
    reporter = ForensicReporter(template_dir)
    output_json = tmp_path / "report.json"

    reporter.generate_json_report(output_json, dummy_case_info, dummy_evidence)

    assert output_json.exists()
    content = output_json.read_text(encoding="utf-8")
    assert "TEST-001" in content
    assert "+12345" in content
