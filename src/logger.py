import logging
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class UTCFormatter(logging.Formatter):
    """
    Custom formatter to provide UTC timestamps in ISO format with 'Z' suffix.
    """

    def formatTime(self, record: logging.LogRecord,
                   datefmt: Optional[str] = None) -> str:
        """Formats the time to ISO 8601 UTC format with milliseconds."""
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        if datefmt:
            return dt.strftime(datefmt)
        # 2024-11-14T10:32:01.441Z format
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class ForensicLogger:
    """
    Thread-safe forensic logger that handles logging to both console and file.
    Ensures UTC timestamps and consistent formatting across the tool.
    """

    _lock = threading.Lock()

    def __init__(self, log_dir: Optional[Path] = None,
                 log_name: str = "acquisition.log"):
        """
        Initializes the logger. If log_dir is provided, a file handler is added.
        """
        self.logger = logging.getLogger("ForensicAcquisition")
        self.logger.setLevel(logging.INFO)

        with self._lock:
            if not self.logger.handlers:
                # Always add console handler
                fmt = UTCFormatter("%(asctime)s [%(levelname)s] %(message)s")
                console_hdlr = logging.StreamHandler(sys.stdout)
                console_hdlr.setFormatter(fmt)
                self.logger.addHandler(console_hdlr)

            if log_dir:
                self.set_log_file(log_dir / log_name)

    def _flush_handlers(self) -> None:
        """Ensures all log entries are written to disk immediately."""
        for handler in self.logger.handlers:
            handler.flush()

    def log_info(self, message: str) -> None:
        """Logs an informational message."""
        self.logger.info(message)
        self._flush_handlers()

    def log_warning(self, message: str) -> None:
        """Logs a warning message."""
        self.logger.warning(message)
        self._flush_handlers()

    def log_error(self, message: str, exc_info: bool = False) -> None:
        """Logs an error message with optional exception info."""
        self.logger.error(message, exc_info=exc_info)
        self._flush_handlers()

    def set_log_file(self, log_file: Path) -> None:
        """
        Dynamically adds a file handler to the logger.
        """
        with self._lock:
            for h in self.logger.handlers:
                if isinstance(h, logging.FileHandler):
                    return

            fmt = UTCFormatter("%(asctime)s [%(levelname)s] %(message)s")
            log_file.parent.mkdir(parents=True, exist_ok=True)
            file_hdlr = logging.FileHandler(
                log_file, mode="a", encoding="utf-8"
            )
            file_hdlr.setFormatter(fmt)
            self.logger.addHandler(file_hdlr)
