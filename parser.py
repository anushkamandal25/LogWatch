"""
LogWatch - Log Parser Module

Parses nginx/apache access logs in combined or common log format.
Extracts: IP address, HTTP method, request path, status code, timestamp.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional


@dataclass
class LogEntry:
    """Represents a single parsed log entry."""

    ip_address: str
    http_method: str
    request_path: str
    status_code: int
    timestamp: datetime

    def __str__(self) -> str:
        return f"{self.ip_address} {self.http_method} {self.request_path} {self.status_code}"


# Regex for combined/common log format:
# IP - - [timestamp] "METHOD path HTTP/x.x" status ...
# Supports IPv4 and IPv6 addresses
LOG_PATTERN = re.compile(
    r'^(?P<ip>[\w.:]+)\s+'  # IP (IPv4, IPv6, or hostname)
    r'-\s+-\s+'  # identd and user (usually -)
    r'\[(?P<timestamp>[^\]]+)\]\s+'  # [timestamp]
    r'"(?P<method>\w+)\s+(?P<path>[^\s]+)\s+HTTP/\d+\.\d+"\s+'  # "METHOD path HTTP/1.1"
    r'(?P<status>\d{3})',  # status code
    re.UNICODE,
)


def parse_timestamp(ts_str: str) -> Optional[datetime]:
    """
    Parse log timestamp (e.g., '14/Mar/2025:10:15:32 +0000') to datetime.
    Returns None if parsing fails.
    """
    try:
        # Remove timezone for parsing; format: 14/Mar/2025:10:15:32 +0000
        return datetime.strptime(ts_str[:20], "%d/%b/%Y:%H:%M:%S")
    except (ValueError, IndexError):
        return None


def parse_line(line: str) -> Optional[LogEntry]:
    """
    Parse a single log line into a LogEntry.
    Returns None if the line doesn't match the expected format.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    match = LOG_PATTERN.search(line)
    if not match:
        return None

    groups = match.groupdict()
    timestamp = parse_timestamp(groups["timestamp"])
    if timestamp is None:
        return None

    try:
        status_code = int(groups["status"])
    except ValueError:
        return None

    return LogEntry(
        ip_address=groups["ip"],
        http_method=groups["method"].upper(),
        request_path=groups["path"],
        status_code=status_code,
        timestamp=timestamp,
    )


def parse_file(filepath: Path) -> Iterator[LogEntry]:
    """
    Parse a log file and yield LogEntry objects.
    Skips empty lines, comments, and malformed entries.
    """
    with open(filepath, encoding="utf-8", errors="replace") as f:
        for line in f:
            entry = parse_line(line)
            if entry is not None:
                yield entry


def parse_files(filepaths: list[Path]) -> list[LogEntry]:
    """
    Parse multiple log files and return a list of all LogEntry objects.
    """
    entries: list[LogEntry] = []
    for path in filepaths:
        if path.exists():
            entries.extend(parse_file(path))
    return entries
