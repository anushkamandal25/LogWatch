#!/usr/bin/env python3
"""
LogWatch - Log Generator

Generates realistic nginx/apache-style access logs for testing and benchmarking.
Supports various traffic patterns including normal traffic, bots, attacks, and errors.
"""

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any


class LogGenerator:
    """Generates realistic web server access logs."""

    def __init__(self, seed: int = 42):
        random.seed(seed)
        self.ip_pool = self._generate_ip_pool()
        self.user_agents = self._get_user_agents()
        self.urls = self._get_urls()
        self.referrers = self._get_referrers()

    def _generate_ip_pool(self) -> List[str]:
        """Generate a pool of realistic IP addresses."""
        ips = []
        # Local network IPs
        for i in range(1, 255):
            ips.extend([
                f"192.168.1.{i}",
                f"10.0.0.{i}",
                f"172.16.0.{i}"
            ])

        # External IPs (simulating real traffic)
        external_ranges = [
            (1, 255), (1, 255), (1, 255), (1, 255)  # Random IPs
        ]

        for _ in range(500):
            ip = ".".join(str(random.randint(*r)) for r in external_ranges)
            ips.append(ip)

        return ips

    def _get_user_agents(self) -> List[str]:
        """Get realistic user agent strings."""
        return [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
            "curl/7.68.0",
            "python-requests/2.28.1",
            "Go-http-client/1.1",
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
            "sqlmap/1.6.5#stable (http://sqlmap.org)",
            "nikto/2.1.6",
            "w3af/1.6.49",
        ]

    def _get_urls(self) -> List[str]:
        """Get realistic URL paths."""
        return [
            "/", "/home", "/about", "/contact", "/products", "/services",
            "/blog", "/news", "/faq", "/support", "/login", "/register",
            "/dashboard", "/profile", "/settings", "/api/users", "/api/data",
            "/admin", "/wp-admin", "/wp-login.php", "/phpmyadmin", "/adminer",
            "/.env", "/.git/config", "/server-status", "/phpinfo.php",
            "/test.php", "/backup.sql", "/config.php", "/wp-config.php",
            "/xmlrpc.php", "/readme.txt", "/changelog.txt", "/license.txt",
            "/search?q=admin", "/search?q=password", "/search?q=login",
            "/category/news", "/category/tech", "/tag/python", "/tag/web",
            "/page/1", "/page/2", "/page/3", "/feed", "/sitemap.xml",
            "/robots.txt", "/favicon.ico", "/css/style.css", "/js/app.js",
            "/images/logo.png", "/images/banner.jpg", "/fonts/main.woff",
        ]

    def _get_referrers(self) -> List[str]:
        """Get realistic referrer URLs."""
        return [
            "-",  # Direct access
            "https://www.google.com/",
            "https://www.bing.com/",
            "https://duckduckgo.com/",
            "https://github.com/",
            "https://stackoverflow.com/",
            "https://reddit.com/",
            "https://twitter.com/",
            "https://linkedin.com/",
            "https://facebook.com/",
            "https://example.com/",
            "https://mysite.com/",
        ]

    def generate_entry(self, timestamp: datetime) -> str:
        """Generate a single log entry."""
        ip = random.choice(self.ip_pool)
        method = random.choices(["GET", "POST", "PUT", "DELETE"], weights=[85, 10, 3, 2])[0]
        url = random.choice(self.urls)
        status = self._get_status_code(url, method)
        size = random.randint(100, 10000) if status == 200 else random.randint(0, 1000)
        referrer = random.choice(self.referrers)
        user_agent = random.choice(self.user_agents)

        # Format timestamp
        ts_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")

        return f'{ip} - - [{ts_str}] "{method} {url} HTTP/1.1" {status} {size} "{referrer}" "{user_agent}"'

    def _get_status_code(self, url: str, method: str) -> int:
        """Determine status code based on URL and method."""
        # Suspicious URLs often return 404
        suspicious_paths = ["/admin", "/wp-admin", "/phpmyadmin", "/.env", "/.git", "/server-status"]
        if any(path in url for path in suspicious_paths):
            return random.choices([404, 403, 200], weights=[70, 20, 10])[0]

        # API endpoints
        if "/api/" in url:
            if method == "POST":
                return random.choices([200, 201, 400, 401, 500], weights=[60, 20, 10, 5, 5])[0]
            return random.choices([200, 404, 500], weights=[80, 15, 5])[0]

        # Login attempts
        if "login" in url.lower():
            return random.choices([200, 401, 403], weights=[30, 50, 20])[0]

        # Normal pages
        return random.choices([200, 301, 404, 500], weights=[85, 5, 8, 2])[0]

    def generate_logs(self, num_lines: int, start_time: datetime = None) -> List[str]:
        """Generate multiple log entries."""
        if start_time is None:
            start_time = datetime(2026, 3, 14, 0, 0, 0)

        entries = []
        current_time = start_time

        for i in range(num_lines):
            # Add some time variation (mostly sequential, some bursts)
            if random.random() < 0.1:  # 10% chance of time jump
                current_time += timedelta(seconds=random.randint(1, 300))
            else:
                current_time += timedelta(milliseconds=random.randint(100, 2000))

            entries.append(self.generate_entry(current_time))

        return entries

    def add_attack_patterns(self, entries: List[str], attack_percentage: float = 0.1) -> List[str]:
        """Add attack patterns to existing logs."""
        num_attacks = int(len(entries) * attack_percentage)
        attack_ips = random.sample(self.ip_pool, min(10, len(self.ip_pool)))

        for _ in range(num_attacks):
            # Create burst traffic from single IP
            attack_ip = random.choice(attack_ips)
            attack_time = datetime(2026, 3, 14, random.randint(0, 23), random.randint(0, 59), random.randint(0, 59))

            for j in range(random.randint(50, 200)):  # Burst of requests
                method = random.choice(["GET", "POST"])
                suspicious_urls = ["/admin", "/wp-admin", "/wp-login.php", "/phpmyadmin", "/.env", "/.git/config"]
                url = random.choice(suspicious_urls)
                status = random.choices([404, 403, 200], weights=[60, 30, 10])[0]
                size = random.randint(0, 500)
                referrer = "-"
                user_agent = random.choice(["curl/7.68.0", "python-requests/2.28.1", "sqlmap/1.6.5"])

                ts_str = attack_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
                entry = f'{attack_ip} - - [{ts_str}] "{method} {url} HTTP/1.1" {status} {size} "{referrer}" "{user_agent}"'
                entries.append(entry)
                attack_time += timedelta(milliseconds=random.randint(50, 200))

        random.shuffle(entries)  # Mix attack entries with normal traffic
        return entries


def main():
    """Main entry point for log generation."""
    parser = argparse.ArgumentParser(
        description="Generate realistic nginx/apache access logs for testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python generate_logs.py --lines 1000 --output sample_logs/access_test.log
  python generate_logs.py --lines 50000 --output sample_logs/access_large.log --attacks
        """
    )
    parser.add_argument(
        "--lines", "-l",
        type=int,
        required=True,
        help="Number of log lines to generate"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        required=True,
        help="Output file path"
    )
    parser.add_argument(
        "--attacks", "-a",
        action="store_true",
        help="Include attack patterns (bursts of suspicious requests)"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducible generation (default: 42)"
    )

    args = parser.parse_args()

    # Create output directory if it doesn't exist
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"Generating {args.lines:,} log entries...")

    # Generate logs
    generator = LogGenerator(seed=args.seed)
    entries = generator.generate_logs(args.lines)

    if args.attacks:
        print("Adding attack patterns...")
        entries = generator.add_attack_patterns(entries)

    # Write to file
    with open(args.output, 'w', encoding='utf-8') as f:
        for entry in entries:
            f.write(entry + '\n')

    print(f"Generated {len(entries):,} log entries in {args.output}")


if __name__ == "__main__":
    main()