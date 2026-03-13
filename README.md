# LogWatch

A beginner-friendly Python tool for analyzing nginx/apache web server access logs and identifying abnormal traffic patterns.

## Features

- **Parse** web server logs (combined/common format)
- **Compute statistics**: total requests, top IPs, top URLs, error counts
- **Detect anomalies**: high-request IPs, 404 probing, suspicious patterns
- **Generate** a CLI report with traffic stats, error breakdown, and suspicious activity

## Project Structure

```
LogWatch/
├── main.py              # Entry point, CLI orchestration
├── parser.py            # Log parsing (regex-based)
├── analyzer.py          # Statistics and anomaly detection
├── report.py            # Report generation
├── generate_logs.py     # Log file generator for testing
├── benchmark.py         # Performance benchmarking tool
├── sample_logs/         # Example log files
│   ├── access.log       # Original sample (28 entries)
│   ├── access_small.log # Small test file (100 entries)
│   ├── access_medium.log# Medium test file (5,000 entries)
│   ├── access_large.log # Large test file (50,000+ entries)
│  
└── README.md
```

## Design

### parser.py

- Uses a regex pattern to parse the common/combined log format
- Extracts: IP address, HTTP method, request path, status code, timestamp
- Yields `LogEntry` dataclass objects; skips malformed lines
- Supports multiple log files

### analyzer.py

- **TrafficStats**: Counts requests by IP, URL, method, and status code
- **Anomaly detection**:
  - **High-request IPs**: IPs with requests > mean + 3× standard deviation
  - **High 404 IPs**: IPs with unusually many 404 responses
  - **Suspicious paths**: URLs that frequently return 404 (e.g. probing)
  - **High error rate**: Overall 4xx/5xx rate ≥ 30%

### report.py

- Formats statistics and anomalies into a readable CLI report
- Sections: Traffic Statistics, Error Breakdown, Suspicious Activity

### main.py

- Parses CLI arguments (default: `sample_logs/`)
- Accepts files or directories (finds `*.log` and common names like `access.log`)
- Runs parser → analyzer → report and prints output

## Requirements

- Python 3.10+ (uses `list[X]` type hints; works with 3.9 if you change to `List[X]` from `typing`)
- Standard library only: `re`, `collections`, `datetime`, `pathlib`, `argparse`

## Running the Project

### Step 1: Install Dependencies

No external dependencies required! LogWatch uses only Python's standard library.

```bash
# Ensure you have Python 3.10+
python --version
```

### Step 2: Run Analysis

#### Basic Usage
```bash
# Analyze sample logs (default behavior)
python main.py

# Analyze a specific log file
python main.py sample_logs/access_small.log

# Analyze multiple files
python main.py sample_logs/access_small.log sample_logs/access_medium.log

# Analyze a directory (automatically finds .log files)
python main.py sample_logs/
```

#### Testing Different Log Sizes
```bash
# Small dataset (100 entries) - quick testing
python main.py sample_logs/access_small.log

# Medium dataset (5,000 entries) - moderate testing
python main.py sample_logs/access_medium.log

# Large dataset (50,000+ entries) - performance testing
python main.py sample_logs/access_large.log
```

### Step 3: View the Generated Report

The tool outputs a comprehensive analysis report including:

- **Traffic Statistics**: Total requests, HTTP methods, top IPs and URLs
- **Error Breakdown**: Status code distribution and error rates
- **Suspicious Activity**: Anomalies like high-traffic IPs, 404 probing, attack patterns

#### Example Output
```
============================================================
  LogWatch - Web Server Log Analysis Report
============================================================

============================================================
TRAFFIC STATISTICS
============================================================
Total requests: 100

--- Requests by HTTP Method ---
  GET: 85
  POST: 15

--- Top 10 Most Active IP Addresses ---
  192.168.1.5: 30 (30.0%)
  10.0.0.1: 25 (25.0%)
  ...

--- Top 10 Most Requested URLs ---
  /: 15 (15.0%)
  /api/users: 12 (12.0%)
  ...

============================================================
ERROR BREAKDOWN
============================================================
404 Not Found: 15
500 Internal Server Error: 2
4xx Client Errors (total): 16
5xx Server Errors (total): 2

Overall error rate: 18.0%

============================================================
SUSPICIOUS ACTIVITY & ANOMALIES
============================================================

--- IPs with Unusually High Request Volume ---
  192.168.1.5: 30 requests

--- IPs with High 404 Error Rate ---
  45.33.12.1: 10 404 responses

--- Suspicious Request Patterns ---
  /admin: 8 requests (all 404)
  /wp-admin: 5 requests (all 404)

--- Overall Alert ---
  Moderate error rate detected (>= 15%)
```

### Additional Tools

#### Generate Custom Log Files
```bash
# Generate 10,000 lines of test data
python generate_logs.py --lines 10000 --output sample_logs/access_custom.log

# Generate logs with attack patterns
python generate_logs.py --lines 50000 --output sample_logs/access_attack.log --attacks
```

#### Performance Benchmarking
```bash
# Benchmark a single file
python benchmark.py --file sample_logs/access_medium.log

# Benchmark all sample files
python benchmark.py --all

# Benchmark multiple files together
python benchmark.py --files sample_logs/access_small.log sample_logs/access_medium.log
```

Example benchmark output:
```
Benchmarking: Medium (5,000 lines)
============================================================
Parsing logs...
Analyzing logs...

Results:
Processed 5,000 log entries
Parsing time: 0.045 seconds
Analysis time: 0.023 seconds
Total time: 0.068 seconds
Throughput: 73,529 entries/second
```
  ...

============================================================
ERROR BREAKDOWN
============================================================

404 Not Found: 10
500 Internal Server Error: 3
...

============================================================
SUSPICIOUS ACTIVITY & ANOMALIES
============================================================

--- IPs with Unusually High Request Volume ---
  192.168.1.100: 14 requests

--- IPs with High 404 Error Rate ---
  10.0.0.50: 8 404 responses
...
```

## Log Format

Supports the standard combined/common format:

```
192.168.1.1 - - [14/Mar/2025:10:15:32 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

