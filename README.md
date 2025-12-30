# HTTP Lookup Service

A high-performance FastAPI-based URL threat intelligence service for validating and checking HTTP/HTTPS URLs against known malicious domains and attack patterns.

## Performance

- **Throughput**: 300-400+ requests/second (tested with 1000 concurrent requests)
- **Latency**: ~230ms average response time under load
- **Reliability**: 100% success rate in load tests
- **Scalability**: Low CPU usage (~20-40%) at peak throughput

## Features

- ✅ **Fast URL Validation** - Async FastAPI with regex and port range validation
- ✅ **Domain Reputation** - SQLite database with indexed hostname lookups
- ✅ **Threat Pattern Detection** - Identifies SQL injection, XSS, path traversal, and more
- ✅ **URL Sanitization** - Strips harmful characters and decodes URL-encoded strings
- ✅ **Comprehensive Tests** - 38 test cases covering all functionality
- ✅ **Modern Web UI** - Beautiful search interface and real-time dashboard with RPS/CPU graphs
- ✅ **External Load Testing** - Shell and Python scripts for performance benchmarking
- ✅ **Configurable** - YAML-based configuration for all settings
- ✅ **Docker Support** - Easy deployment with Docker

## Quick Start

### Using Docker (recommended)

```bash
# Build and run
docker build -t httplookup .
docker run -p 8000:8000 httplookup

# Access at http://localhost:8000
```

### Using Scripts

```bash
pip install -r requirements.txt
./run_tests.sh        # Run all tests
./start_server.sh     # Start server (Ctrl+C to stop)
./stop_server.sh      # Stop from another terminal
```

### Manual

```bash
pip install -r requirements.txt
python main.py
# Access at http://localhost:8000
```

## Web Interface

- **Search Page** (`/`) - URL checker with test prompts
- **Dashboard** (`/dashboard`) - Real-time RPS/CPU graphs and metrics
- **API Docs** (`/docs`) - Interactive API documentation

## Load Testing

Use the external load testing script to benchmark performance:

```bash
# Run 1000 requests with 50 concurrent connections (default)
./load_test.sh

# High load test with more concurrency
NUM_REQUESTS=5000 CONCURRENCY=100 ./load_test.sh

# Custom settings
NUM_REQUESTS=10000 CONCURRENCY=200 BASE_URL=http://localhost:8000 ./load_test.sh
```

**Tip:** Install `wrk` for more advanced load testing:

```bash
brew install wrk  # macOS
# Then run ./load_test.sh to use wrk automatically
```

The script provides detailed metrics including RPS, response times, and success rates.

### Benchmark Results

Recent load test results on a standard development machine:

| Test Configuration  | Requests | Concurrency | Throughput    | Success Rate |
| ------------------- | -------- | ----------- | ------------- | ------------ |
| Shell (curl+xargs)  | 1,000    | 100         | **364 req/s** | 100%         |
| Shell (curl+xargs)  | 100      | 20          | **406 req/s** | 100%         |
| Python (httpx)      | 500      | 50          | **123 req/s** | 100%         |

**Latency Metrics** (Python load test, 500 requests):

- Average: 237ms
- P50: 231ms
- P95: 378ms
- P99: 413ms

*Note: Python client adds HTTP overhead. Real server performance is 300-400+ req/s.*

## Automation Scripts

Three convenience scripts are provided for development and testing:

### `run_tests.sh` - Run All Tests

```bash
./run_tests.sh
```

Runs the complete test suite (38 tests) with colored output and clear success/failure messages.

### `start_server.sh` - Start Server

```bash
./start_server.sh
```

Starts the FastAPI server with hot-reload enabled for development. Press `Ctrl+C` to stop gracefully.

Features:

- Auto-reload on code changes
- Reads config from `config.yaml`
- Creates PID file for tracking
- Graceful shutdown handling

### `stop_server.sh` - Stop Server

```bash
./stop_server.sh
```

Stops a running server from another terminal. Uses the PID file to gracefully terminate the process.

## Documentation

- **[DATABASE.md](docs/DATABASE.md)** - Database schema and structure
- **[SECURITY.md](docs/SECURITY.md)** - Security pipeline and validation order
- **[API.md](docs/API.md)** - API endpoints and examples
- **[CONFIG.md](docs/CONFIG.md)** - Configuration options

## Testing

```bash
./run_tests.sh          # All 38 tests
pytest tests/ -v        # Manual run
```
