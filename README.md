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

## Quick Start

### Using the automation scripts (recommended)

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests
./run_tests.sh

# Start the server
./start_server.sh
# Press Ctrl+C to stop, or use ./stop_server.sh from another terminal

# Stop the server (from another terminal)
./stop_server.sh
```

### Manual start

```bash
# Install dependencies
pip install -r requirements.txt

# Configure server (optional - defaults to port 8000)
# Edit config.yaml to change port, host, or other settings

# Run server
python main.py

# Server runs on http://localhost:8000 (or your configured port)
# Access the web interface at http://localhost:8000
# Access the dashboard at http://localhost:8000/dashboard
# Access API docs at http://localhost:8000/docs
```

## Web Interface

The service includes a modern web interface:

- **Search Page** (`/`) - Google-like URL checker with real-time results
- **Dashboard** (`/dashboard`) - Live statistics and monitoring
- **API Docs** (`/docs`) - Interactive API documentation

Simply open `http://localhost:8000` in your browser!

## API Usage

```bash
# Check a URL
curl http://localhost:5000/urlinfo/1/example.com/path/to/resource

# Check with query parameters
curl http://localhost:5000/urlinfo/1/example.com/search?q=test

# Health check
curl http://localhost:5000/health
```

## Documentation

- **API Reference**: [docs/API.md](docs/API.md)
- **Frontend Guide**: [docs/FRONTEND.md](docs/FRONTEND.md) - **How to use the web interface**
- **Configuration Guide**: [docs/CONFIG.md](docs/CONFIG.md) - **How to change port and other settings**
- **Security Architecture**: [docs/SECURITY.md](docs/SECURITY.md) - **Important: Read this to understand the security pipeline**
- **Database Schema**: [databases/SCHEMA.md](databases/SCHEMA.md)
- **Development Process**: [docs/development_process.md](docs/development_process.md)

## Testing

```bash
# Run all tests (using automation script)
./run_tests.sh

# Or run manually
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=main
```

## Project Status

Current version includes core URL validation and threat detection. Future enhancements planned:

- Configuration modes (permissive/restrictive)
- Redis caching layer
- Load balancer integration
- Monitoring dashboard

FastAPI-based URL validation service.
