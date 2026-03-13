"""
LogWatch - Log Analyzer Module

Computes traffic statistics and detects simple anomalies in log data.
"""

from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from parser import LogEntry


@dataclass
class TrafficStats:
    """Container for computed traffic statistics."""

    total_requests: int = 0
    requests_by_ip: Counter = field(default_factory=Counter)
    requests_by_url: Counter = field(default_factory=Counter)
    requests_by_method: Counter = field(default_factory=Counter)
    status_counts: Counter = field(default_factory=Counter)
    error_404_count: int = 0
    error_500_count: int = 0
    error_4xx_count: int = 0
    error_5xx_count: int = 0


@dataclass
class AnomalyReport:
    """Container for detected anomalies."""

    high_request_ips: list[tuple[str, int]] = field(default_factory=list)
    high_404_ips: list[tuple[str, int]] = field(default_factory=list)
    suspicious_paths: list[tuple[str, int]] = field(default_factory=list)
    high_error_rate: bool = False


def compute_statistics(entries: list["LogEntry"]) -> TrafficStats:
    """
    Compute traffic statistics from parsed log entries.
    """
    stats = TrafficStats()

    for entry in entries:
        stats.total_requests += 1
        stats.requests_by_ip[entry.ip_address] += 1
        stats.requests_by_url[entry.request_path] += 1
        stats.requests_by_method[entry.http_method] += 1
        stats.status_counts[entry.status_code] += 1

        if entry.status_code == 404:
            stats.error_404_count += 1
        elif entry.status_code == 500:
            stats.error_500_count += 1

        if 400 <= entry.status_code < 500:
            stats.error_4xx_count += 1
        elif 500 <= entry.status_code < 600:
            stats.error_5xx_count += 1

    return stats


def detect_anomalies(
    entries: list["LogEntry"],
    stats: TrafficStats,
    *,
    ip_threshold_multiplier: float = 3.0,
    error_rate_threshold: float = 0.3,
    top_n: int = 5,
) -> AnomalyReport:
    """
    Detect simple anomalies in traffic patterns.

    - High-request IPs: IPs with requests > mean + (multiplier * std_dev)
    - High 404 IPs: IPs with unusually many 404 responses
    - Suspicious paths: URLs that returned many 404s (potential probing)
    - High error rate: Overall 4xx/5xx rate exceeds threshold
    """
    report = AnomalyReport()

    if not entries:
        return report

    # 1. High-request IPs (above mean + threshold * std_dev)
    ip_counts = list(stats.requests_by_ip.values())
    if ip_counts:
        mean_requests = sum(ip_counts) / len(ip_counts)
        variance = sum((x - mean_requests) ** 2 for x in ip_counts) / len(ip_counts)
        std_dev = variance**0.5 if variance > 0 else 0
        threshold = mean_requests + (ip_threshold_multiplier * std_dev)

        for ip, count in stats.requests_by_ip.most_common():
            # Flag if above threshold, or if 2x+ the mean (for small samples)
            if (count > threshold or count >= 2 * mean_requests) and count > 1:
                report.high_request_ips.append((ip, count))
        report.high_request_ips.sort(key=lambda x: -x[1])
        report.high_request_ips = report.high_request_ips[:top_n]

    # 2. High 404 IPs - count 404s per IP
    ip_404_counts: Counter = Counter()
    for entry in entries:
        if entry.status_code == 404:
            ip_404_counts[entry.ip_address] += 1

    if ip_404_counts:
        mean_404 = sum(ip_404_counts.values()) / len(ip_404_counts)
        for ip, count in ip_404_counts.most_common(top_n):
            # Flag IPs with 3+ 404s or above-average 404s
            if count >= 3 or (count > mean_404 and count >= 2):
                report.high_404_ips.append((ip, count))

    # 3. Suspicious paths - URLs with many 404s (probing for vulnerabilities)
    path_404_counts: Counter = Counter()
    for entry in entries:
        if entry.status_code == 404:
            path_404_counts[entry.request_path] += 1

    for path, count in path_404_counts.most_common(top_n):
        if count >= 2:
            report.suspicious_paths.append((path, count))

    # 4. High overall error rate
    error_count = stats.error_4xx_count + stats.error_5xx_count
    error_rate = error_count / stats.total_requests if stats.total_requests > 0 else 0
    report.high_error_rate = error_rate >= error_rate_threshold

    return report
