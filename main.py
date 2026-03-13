#!/usr/bin/env python3
"""
LogWatch - Web Server Log Monitoring Tool

Analyzes nginx/apache access logs and identifies abnormal traffic patterns.
Usage: python main.py [log_file_or_directory ...]
"""

import argparse
import sys
from pathlib import Path

from analyzer import compute_statistics, detect_anomalies
from parser import parse_files
from report import generate_full_report


def collect_log_paths(paths: list[str]) -> list[Path]:
    """
    Collect all log file paths from the given arguments.
    Supports both files and directories (recursively finds .log files).
    """
    result: list[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_file():
            result.append(path)
        elif path.is_dir():
            result.extend(path.rglob("*.log"))
            # Also include common access log names without .log extension
            for name in ("access.log", "access_log", "error.log"):
                access_log = path / name
                if access_log.exists() and access_log not in result:
                    result.append(access_log)
        else:
            print(f"Warning: '{p}' does not exist, skipping.", file=sys.stderr)
    return result


def main() -> int:
    """Entry point for LogWatch CLI."""
    parser = argparse.ArgumentParser(
        description="LogWatch - Analyze web server logs and detect anomalies",
        epilog="Example: python main.py sample_logs/access.log",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["sample_logs"],
        help="Log files or directories to analyze (default: sample_logs)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress warnings about missing files",
    )
    args = parser.parse_args()

    # Collect log file paths
    log_paths = collect_log_paths(args.paths)
    if not log_paths:
        print("Error: No log files found.", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"Analyzing {len(log_paths)} log file(s)...", file=sys.stderr)

    # Parse logs
    entries = parse_files(log_paths)
    if not entries:
        print("Error: No valid log entries found.", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"Parsed {len(entries)} log entries.", file=sys.stderr)

    # Compute statistics and detect anomalies
    stats = compute_statistics(entries)
    anomalies = detect_anomalies(entries, stats)

    # Generate and print report
    report = generate_full_report(stats, anomalies)
    print(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
