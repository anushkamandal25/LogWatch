#!/usr/bin/env python3
"""
LogWatch - Performance Benchmarking

Measures parsing and analysis performance for different log file sizes.
"""

import time
import argparse
from pathlib import Path
from typing import List, Tuple

from analyzer import compute_statistics, detect_anomalies
from parser import parse_files


def benchmark_parsing(log_files: List[Path]) -> Tuple[int, float]:
    """Benchmark log parsing performance."""
    start_time = time.time()
    entries = parse_files(log_files)
    end_time = time.time()

    parsing_time = end_time - start_time
    return len(entries), parsing_time


def benchmark_analysis(entries: List) -> Tuple[dict, dict, float]:
    """Benchmark anomaly detection performance."""
    start_time = time.time()
    stats = compute_statistics(entries)
    anomalies = detect_anomalies(entries, stats)
    end_time = time.time()

    analysis_time = end_time - start_time
    return stats, anomalies, analysis_time


def benchmark_file(file_path: str, description: str = "") -> None:
    """Benchmark a single log file."""
    log_path = Path(file_path)
    if not log_path.exists():
        print(f"Error: File {file_path} does not exist")
        return

    print(f"\n{'='*60}")
    print(f"Benchmarking: {description or file_path}")
    print(f"{'='*60}")

    # Benchmark parsing
    print("Parsing logs...")
    num_entries, parsing_time = benchmark_parsing([log_path])

    # Benchmark analysis
    print("Analyzing logs...")
    from parser import parse_files  # Re-import to get entries
    entries = parse_files([log_path])
    stats, anomalies, analysis_time = benchmark_analysis(entries)

    total_time = parsing_time + analysis_time

    # Print results
    print(f"\nResults:")
    print(f"Processed {num_entries:,} log entries")
    print(f"Parsing time: {parsing_time:.3f} seconds")
    print(f"Analysis time: {analysis_time:.3f} seconds")
    print(f"Total time: {total_time:.3f} seconds")
    print(f"Throughput: {num_entries / total_time:.0f} entries/second")

    # Basic stats
    if stats:
        print(f"\nQuick Stats:")
        print(f"  Unique IPs: {len(stats.requests_by_ip)}")
        print(f"  Total requests: {stats.total_requests}")
        print(f"  Error rate: {stats.error_4xx_count + stats.error_5xx_count}/{stats.total_requests} ({(stats.error_4xx_count + stats.error_5xx_count) / max(stats.total_requests, 1) * 100:.1f}%)")


def benchmark_multiple_files(file_paths: List[str]) -> None:
    """Benchmark multiple files together."""
    log_paths = [Path(p) for p in file_paths if Path(p).exists()]

    if not log_paths:
        print("Error: No valid files found")
        return

    print(f"\n{'='*60}")
    print(f"Benchmarking multiple files: {len(log_paths)} files")
    print(f"{'='*60}")

    # Benchmark parsing
    print("Parsing logs...")
    num_entries, parsing_time = benchmark_parsing(log_paths)

    # Benchmark analysis
    print("Analyzing logs...")
    from parser import parse_files
    entries = parse_files(log_paths)
    stats, anomalies, analysis_time = benchmark_analysis(entries)

    total_time = parsing_time + analysis_time

    print(f"\nResults:")
    print(f"Processed {num_entries:,} log entries from {len(log_paths)} files")
    print(f"Parsing time: {parsing_time:.3f} seconds")
    print(f"Analysis time: {analysis_time:.3f} seconds")
    print(f"Total time: {total_time:.3f} seconds")
    print(f"Throughput: {num_entries / total_time:.0f} entries/second")


def main():
    """Main entry point for benchmarking."""
    parser = argparse.ArgumentParser(
        description="Benchmark LogWatch performance on log files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python benchmark.py --file sample_logs/access_small.log
  python benchmark.py --files sample_logs/access_small.log sample_logs/access_medium.log
  python benchmark.py --all
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--file", "-f",
        type=str,
        help="Benchmark a single log file"
    )
    group.add_argument(
        "--files", "-m",
        nargs="+",
        help="Benchmark multiple log files together"
    )
    group.add_argument(
        "--all", "-a",
        action="store_true",
        help="Benchmark all sample log files"
    )

    args = parser.parse_args()

    if args.file:
        benchmark_file(args.file)
    elif args.files:
        benchmark_multiple_files(args.files)
    elif args.all:
        # Benchmark all sample files
        sample_files = [
            ("sample_logs/access_small.log", "Small (100 lines)"),
            ("sample_logs/access_medium.log", "Medium (5,000 lines)"),
            ("sample_logs/access_large.log", "Large (50,000+ lines)"),
        ]

        for file_path, description in sample_files:
            if Path(file_path).exists():
                benchmark_file(file_path, description)
            else:
                print(f"Warning: {file_path} not found, skipping")


if __name__ == "__main__":
    main()