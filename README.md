# HTTP Lookup Service

A high-performance FastAPI-based URL threat intelligence service for validating and checking HTTP/HTTPS URLs against known malicious domains and attack patterns.

## Features

- ✅ **Fast URL Validation** - Async FastAPI with regex and port range validation
- ✅ **Domain Reputation** - SQLite database with indexed hostname lookups
- ✅ **Threat Pattern Detection** - Identifies SQL injection, XSS, path traversal, and more
- ✅ **URL Sanitization** - Strips harmful characters and decodes URL-encoded strings
- ✅ **Comprehensive Tests** - 38 test cases covering all functionality
- ✅ **Modern Web UI** - Beautiful search interface and real-time dashboard
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

The service includes a modern web interface:

- **Search Page** (`/`) - Google-like URL checker with real-time results
## Web Interface

- **Search Page** (`/`) - URL checker with test prompts
- **Dashboard** (`/dashboard`) - Real-time stats, graphs, and stress testing
- **API Docs** (`/docs`) - Interactive API documentation

## Documentation

See [docs/](docs/) for API reference, configuration, and security details.

## Testing

```bash
./run_tests.sh          # All 38 tests
pytest tests/ -v        # Manual run
```
