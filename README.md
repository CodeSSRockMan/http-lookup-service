# HTTP Lookup Service

A high-performance FastAPI-based URL threat intelligence service for validating and checking HTTP/HTTPS URLs against known malicious domains and attack patterns.

## Features

- ✅ **Fast URL Validation** - Async FastAPI with regex and port range validation
- ✅ **Domain Reputation** - SQLite database with indexed hostname lookups
- ✅ **Threat Pattern Detection** - Identifies SQL injection, XSS, path traversal, and more
- ✅ **URL Sanitization** - Strips harmful characters and decodes URL-encoded strings
- ✅ **Comprehensive Tests** - 38 test cases covering all functionality

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run server
python main.py

# Server runs on http://localhost:5000
```

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
- **Database Schema**: [databases/SCHEMA.md](databases/SCHEMA.md)
- **Development Process**: [docs/development_process.md](docs/development_process.md)

## Testing

```bash
# Run all tests
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
