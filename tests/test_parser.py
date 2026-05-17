import os
import tempfile
import sqlite3
import pytest
from pathlib import Path
from src.parser import SMSParser, CallLogParser, BrowserParser


@pytest.fixture
def mock_sms_db(tmp_path):
    db_path = tmp_path / "mmssms.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "CREATE TABLE sms (address TEXT, date INTEGER, body TEXT, type INTEGER, read INTEGER)")
    cursor.execute(
        "INSERT INTO sms VALUES ('+1234567890', 1628701402000, 'Test message', 1, 1)")
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture
def mock_calllog_db(tmp_path):
    db_path = tmp_path / "calllog.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "CREATE TABLE calls (number TEXT, date INTEGER, duration INTEGER, type INTEGER, name TEXT)")
    cursor.execute(
        "INSERT INTO calls VALUES ('9876543210', 1628701402000, 45, 2, 'John Doe')")
    conn.commit()
    conn.close()
    return db_path


def test_sms_parser_correctness(mock_sms_db):
    parser = SMSParser(mock_sms_db)
    messages = parser.parse_messages()
    assert len(messages) == 1
    assert messages[0]["address"] == "+1234567890"
    assert messages[0]["body"] == "Test message"


def test_calllog_parser_correctness(mock_calllog_db):
    parser = CallLogParser(mock_calllog_db)
    calls = parser.parse_calls()
    assert len(calls) == 1
    assert calls[0]["number"] == "9876543210"
    assert calls[0]["duration"] == 45
    assert calls[0]["name"] == "John Doe"


def test_browser_parser_inaccessible_db(tmp_path):
    # Testing inaccessible DB handling (e.g. file doesn't exist)
    missing_db = tmp_path / "missing_chrome.db"
    parser = BrowserParser(missing_db)
    history = parser.parse_history()
    # Should return empty list and not crash
    assert isinstance(history, list)
    assert len(history) == 0


def test_zero_byte_file_handling(tmp_path):
    zero_byte_db = tmp_path / "zero_byte.db"
    zero_byte_db.touch()  # Create empty file
    parser = CallLogParser(zero_byte_db)
    calls = parser.parse_calls()
    # sqlite3 parsing an empty file throws DatabaseError which should be caught
    assert isinstance(calls, list)
    assert len(calls) == 0
