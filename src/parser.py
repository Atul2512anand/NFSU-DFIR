"""
Module for forensic acquisition.
"""

import sqlite3
from pathlib import Path
from typing import Any, Dict, List
from .logger import ForensicLogger

# Initialize logger for this module
logger = ForensicLogger()


class SQLiteForensicParser:
    """
    Base class for forensic SQLite database parsing.
    Provides safe connection and query execution.
    """

    def __init__(self, db_path: Path):
        """Function documentation."""

        self.db_path = db_path

    def _query_db(self, query: str) -> List[Dict[str, Any]]:
        """Executes a query and returns results as a list of dictionaries."""
        results = []
        if not self.db_path.exists():
            logger.log_error(f"Database not found: {self.db_path}")
            return results

        try:
            # Connect in read-only mode for forensic integrity
            conn = sqlite3.connect(
                f"file:{self.db_path}?mode=ro", uri=True
            )
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query)

            results = [dict(row) for row in cursor.fetchall()]
            conn.close()
        except sqlite3.Error as e:
            logger.log_error(
                f"SQLite error while parsing {self.db_path.name}: {e}"
            )

        return results


class SMSParser(SQLiteForensicParser):
    """Parses Android SMS/MMS database (mmssms.db)."""

    def parse_messages(self) -> List[Dict[str, Any]]:
        """Extracts SMS messages from the 'sms' table."""
        query = "SELECT address, date, body, type, read FROM sms"
        return self._query_db(query)


class CallLogParser(SQLiteForensicParser):
    """Parses Android Call Log database (calllog.db)."""

    def parse_calls(self) -> List[Dict[str, Any]]:
        """Extracts call records from the 'calls' table."""
        query = "SELECT number, date, duration, type, name FROM calls"
        return self._query_db(query)


class BrowserParser(SQLiteForensicParser):
    """Parses Browser History (Chrome/Stock) database."""

    def parse_history(self) -> List[Dict[str, Any]]:
        """
        Extracts visited URLs from the Chrome 'urls' table.
        Chrome stores last_visit_time as microseconds since Jan 1, 1601
        (Windows FILETIME epoch). The SQL converts this to a UTC string.
        """
        query = (
            "SELECT url, title, visit_count, "
            "datetime(last_visit_time / 1000000 - 11644473600, 'unixepoch') "
            "AS last_visit "
            "FROM urls "
            "ORDER BY last_visit_time DESC"
        )
        return self._query_db(query)
