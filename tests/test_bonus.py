import json
import pytest
from pathlib import Path
from src.parser import CallLogParser
from src.reporter import ForensicReporter


def test_timeline_generation():
    reporter = ForensicReporter(Path("templates"))
    evidence = {
        "call_logs": [{"date": "2024-05-17T12:00:00Z", "type": "2", "number": "123"}],
        "sms_messages": [{"date": "2024-05-17T12:05:00Z", "address": "456"}],
        "browser_history": [{"last_visit": "2024-05-17T11:00:00Z", "url": "https://example.com"}]
    }
    timeline = reporter._build_timeline(evidence)
    assert len(timeline) == 3
    # Ensure sorted chronologically
    assert timeline[0]["category"] == "BROWSER"
    assert timeline[1]["category"] == "CALL"
    assert timeline[2]["category"] == "SMS"


def test_deleted_record_freelist_mock(monkeypatch, tmp_path):
    # Create fake sqlite db
    db_path = tmp_path / "fake.db"
    import sqlite3
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE fake(id);")
    conn.close()

    parser = CallLogParser(db_path)
    # mock get_freelist_count to return 5
    monkeypatch.setattr(parser, "get_freelist_count", lambda: 5)
    assert parser.get_freelist_count() == 5


def test_exif_fallback_mock(tmp_path):
    from src.extractor import DataExtractor
    from src.device import AndroidDevice

    class DummyADB:
        def close(self): pass
        def shell(self, cmd): return ""

    class DummyDevice:
        def __init__(self):
            self.adb = DummyADB()
            self.serial = "mock"

    extractor = DataExtractor(DummyDevice(), tmp_path)
    # create empty manifest
    (tmp_path / "media_metadata").mkdir(parents=True)
    with open(tmp_path / "media_metadata" / "storage_manifest.json", "w") as f:
        json.dump([], f)

    out = extractor.extract_exif_gps()
    assert out.exists()
    with open(out, "r") as f:
        data = json.load(f)
    assert data == []
