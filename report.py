"""
LogWatch - Report Generation Module

Generates a human-readable CLI report from traffic statistics and anomaly data.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from analyzer import AnomalyReport, TrafficStats


def format_section(title: str, width: int = 60) -> str:
    """Format a section header with a separator line."""
    return f"\n{'=' * width}\n{title}\n{'=' * width}\n"


def format_subsection(title: str) -> str:
    """Format a subsection header."""
    return f"\n--- {title} ---\n"


def generate_traffic_report(stats: "TrafficStats") -> str:
    """Generate the traffic statistics section of the report."""
    lines: list[str] = []

    lines.append(format_section("TRAFFIC STATISTICS"))

    lines.append(f"Total requests: {stats.total_requests}\n")

    lines.append(format_subsection("Requests by HTTP Method"))
    for method, count in stats.requests_by_method.most_common():
        lines.append(f"  {method}: {count}\n")

    lines.append(format_subsection("Top 10 Most Active IP Addresses"))
    for ip, count in stats.requests_by_ip.most_common(10):
        pct = (count / stats.total_requests * 100) if stats.total_requests > 0 else 0
        lines.append(f"  {ip}: {count} ({pct:.1f}%)\n")

    lines.append(format_subsection("Top 10 Most Requested URLs"))
    for url, count in stats.requests_by_url.most_common(10):
        pct = (count / stats.total_requests * 100) if stats.total_requests > 0 else 0
        lines.append(f"  {url}: {count} ({pct:.1f}%)\n")

    return "".join(lines)


def generate_error_report(stats: "TrafficStats") -> str:
    """Generate the error breakdown section of the report."""
    lines: list[str] = []

    lines.append(format_section("ERROR BREAKDOWN"))

    lines.append(f"404 Not Found: {stats.error_404_count}\n")
    lines.append(f"500 Internal Server Error: {stats.error_500_count}\n")
    lines.append(f"4xx Client Errors (total): {stats.error_4xx_count}\n")
    lines.append(f"5xx Server Errors (total): {stats.error_5xx_count}\n")

    if stats.total_requests > 0:
        error_total = stats.error_4xx_count + stats.error_5xx_count
        error_rate = error_total / stats.total_requests * 100
        lines.append(f"\nOverall error rate: {error_rate:.1f}%\n")

    lines.append(format_subsection("Status Code Distribution"))
    for code, count in sorted(stats.status_counts.items()):
        pct = (count / stats.total_requests * 100) if stats.total_requests > 0 else 0
        lines.append(f"  {code}: {count} ({pct:.1f}%)\n")

    return "".join(lines)


def generate_anomaly_report(anomalies: "AnomalyReport") -> str:
    """Generate the suspicious activity section of the report."""
    lines: list[str] = []

    lines.append(format_section("SUSPICIOUS ACTIVITY & ANOMALIES"))

    if anomalies.high_request_ips:
        lines.append(format_subsection("IPs with Unusually High Request Volume"))
        for ip, count in anomalies.high_request_ips:
            lines.append(f"  {ip}: {count} requests\n")
    else:
        lines.append(format_subsection("IPs with Unusually High Request Volume"))
        lines.append("  None detected\n")

    if anomalies.high_404_ips:
        lines.append(format_subsection("IPs with High 404 Error Rate"))
        for ip, count in anomalies.high_404_ips:
            lines.append(f"  {ip}: {count} 404 responses\n")
    else:
        lines.append(format_subsection("IPs with High 404 Error Rate"))
        lines.append("  None detected\n")

    if anomalies.suspicious_paths:
        lines.append(format_subsection("Suspicious Request Patterns (frequent 404s)"))
        for path, count in anomalies.suspicious_paths:
            lines.append(f"  {path}: {count} 404s\n")
    else:
        lines.append(format_subsection("Suspicious Request Patterns (frequent 404s)"))
        lines.append("  None detected\n")

    if anomalies.high_error_rate:
        lines.append(format_subsection("Overall Alert"))
        lines.append("  WARNING: High overall error rate detected (>= 30%)\n")

    return "".join(lines)


def generate_full_report(
    stats: "TrafficStats",
    anomalies: "AnomalyReport",
) -> str:
    """Generate the complete CLI report."""
    lines: list[str] = []

    lines.append("\n" + "=" * 60 + "\n")
    lines.append("  LogWatch - Web Server Log Analysis Report\n")
    lines.append("=" * 60 + "\n")

    lines.append(generate_traffic_report(stats))
    lines.append(generate_error_report(stats))
    lines.append(generate_anomaly_report(anomalies))

    lines.append("\n" + "=" * 60 + "\n")
    lines.append("  End of Report\n")
    lines.append("=" * 60 + "\n")

    return "".join(lines)
