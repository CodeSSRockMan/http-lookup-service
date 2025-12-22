# HTTP Lookup Service - Technical Documentation

## Overview

A high-performance FastAPI-based URL threat intelligence service that validates HTTP/HTTPS URLs and checks them against a database of known malicious domains and attack patterns.

## Architecture

### Technology Stack

- **Framework**: FastAPI 0.109.0 (async ASGI)
- **Server**: Uvicorn 0.25.0
- **Database**: SQLite with aiosqlite (async)
- **Testing**: pytest with 38 test cases
- **Python**: 3.11+

### Core Components

``` text
┌─────────────────────────────────────────────────────────────┐
│                    HTTP Lookup Service                       │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼
        ┌──────────────────────────────────────┐
        │     FastAPI Application (main.py)     │
        └──────────────────────────────────────┘
                           │
        ┌──────────────────┴──────────────────┐
        │                                      │
        ▼                                      ▼
┌──────────────┐                     ┌──────────────┐
│  Validation  │                     │   Database   │
│   Pipeline   │                     │   Lookups    │
└──────────────┘                     └──────────────┘
        │                                      │
        ├─ Sanitize URL                       ├─ Domain Reputation
        ├─ Decode URL Parts                   ├─ Malicious Patterns
        ├─ Validate Format (Regex)            └─ SQLite (aiosqlite)
        └─ Check Port Range
```

---

## API Endpoints

### 1. URL Lookup

**Endpoint**: `GET /urlinfo/1/{url_parts:path}`

**Format**: `/urlinfo/1/{hostname_and_port}/{original_path_and_query_string}`

**Examples**:

```bash
GET /urlinfo/1/example.com/path/to/resource
GET /urlinfo/1/example.com:8080/api/v1/users
GET /urlinfo/1/https://example.com/search?q=test
```

**Response** (200 OK):

```json
{
  "valid": true,
  "url": "http://example.com/path/to/resource",
  "lookup_result": {
    "found": true,
    "hostname": "example.com",
    "status": "safe",
    "description": "Example domain - safe for testing",
    "last_updated": "2025-12-22 10:30:00"
  },
  "malicious_patterns": {
    "found": false
  }
}
```

**Response with Threat** (200 OK):

```json
{
  "valid": true,
  "url": "http://malicious-site.com/path",
  "lookup_result": {
    "found": true,
    "hostname": "malicious-site.com",
    "status": "malicious",
    "description": "Known malware distribution site",
    "last_updated": "2025-12-22 10:30:00"
  },
  "malicious_patterns": {
    "found": true,
    "pattern": "SELECT * FROM",
    "pattern_type": "query_param",
    "threat_type": "sql_injection",
    "description": "SQL injection attempt"
  }
}
```

**Error Response** (400 Bad Request):

```json
{
  "detail": {
    "error": "Invalid HTTP URL",
    "message": "URL does not match valid HTTP/HTTPS format",
    "url": "invalid://example"
  }
}
```

### 2. Health Check

**Endpoint**: `GET /health`

**Response** (200 OK):

```json
{
  "status": "healthy"
}
```

---

## URL Processing Pipeline

### Step 1: URL Reconstruction

``` text
Input: /urlinfo/1/example.com:8080/api/users?id=1
          ↓
Parse: hostname_and_port = "example.com:8080"
       path_and_query = "api/users?id=1"
          ↓
Reconstruct: "http://example.com:8080/api/users?id=1"
```

### Step 2: Sanitization

- Remove leading/trailing whitespace
- Strip null bytes (`\x00`)
- Remove control characters (`\x01-\x1f`, `\x7f`)

### Step 3: URL Decoding

- **Hostname/Path**: `unquote()` - Decodes %20 → space
- **Query String**: `unquote_plus()` - Decodes + → space, %20 → space

### Step 4: Validation

- **Regex**: Matches HTTP/HTTPS format
- **Port Check**: Range 1-65535
- **Hostname**: Must exist and be non-empty

### Step 5: Threat Detection

1. Extract hostname → Query `domains` table
2. Extract path/query → Match against `malicious_queries` patterns
3. Return combined results

---

## Functions Reference

### URL Processing Functions

#### `sanitize_url(url: str) -> str`

Removes harmful characters from URL.

**Parameters**:

- `url`: Raw URL string

**Returns**: Sanitized URL string

**Example**:

```python
sanitize_url("  http://example.com\x00  ")
# Returns: "http://example.com"
```

---

#### `decode_url_parts(url: str) -> str`

Decodes URL-encoded characters.

**Parameters**:

- `url`: URL with encoded characters

**Returns**: Decoded URL string

**Example**:

```python
decode_url_parts("http://example.com/path%20with%20spaces?q=hello+world")
# Returns: "http://example.com/path with spaces?q=hello world"
```

---

#### `validate_url_regex(url: str) -> bool`

Validates URL format and port range.

**Parameters**:

- `url`: URL to validate

**Returns**: `True` if valid, `False` otherwise

**Validation Rules**:

- Scheme must be `http://` or `https://`
- Hostname required (non-empty)
- Port range: 1-65535 (if specified)
- Supports subdomains and paths

**Example**:

```python
validate_url_regex("http://example.com:8080/path")  # True
validate_url_regex("http://example.com:99999")      # False (invalid port)
validate_url_regex("ftp://example.com")             # False (wrong scheme)
```

---

### Database Functions

#### `async lookup_domain(hostname: str) -> dict | None`

Queries domain reputation database.

**Parameters**:

- `hostname`: Domain hostname (e.g., "example.com")

**Returns**: Domain info dict or `None` if not found

**Example**:

```python
result = await lookup_domain("malicious-site.com")
# Returns: {'hostname': 'malicious-site.com', 'status': 'malicious', ...}
```

---

#### `async check_malicious_patterns(url: str) -> dict | None`

Scans URL for malicious patterns.

**Parameters**:

- `url`: Full URL to check

**Returns**: Pattern info dict or `None` if clean

**Example**:

```python
result = await check_malicious_patterns("http://example.com/path?q=<script>")
# Returns: {'pattern': '<script>', 'threat_type': 'xss', ...}
```

---

## Database Schema

See [databases/SCHEMA.md](databases/SCHEMA.md) for detailed schema documentation.

**Quick Reference**:

- **domains**: 8 demo entries (safe, malicious, phishing, blacklisted)
- **malicious_queries**: 10 attack patterns (SQL injection, XSS, path traversal, etc.)

---

## Configuration

### Database

- **Path**: `databases/lookup.db`
- **Type**: SQLite (file-based)
- **Initialization**: Automatic on startup via lifespan event
- **Concurrency**: Read-only safe for multiple instances

### Server

- **Host**: `0.0.0.0` (all interfaces)
- **Port**: `5000`
- **Mode**: Development (debug mode disabled in production)

---

## Testing

### Run All Tests

```bash
pytest tests/ -v
```

### Run Specific Test Suite

```bash
pytest tests/test_main.py::TestDatabaseLookup -v
pytest tests/test_main.py::TestMaliciousPatterns -v
```

### Test Coverage

- **Total Tests**: 38
- **Categories**:
  - URL Sanitization (3 tests)
  - URL Decoding (4 tests)
  - Regex Validation (10 tests)
  - Endpoint Behavior (10 tests)
  - Database Lookups (5 tests)
  - Malicious Patterns (4 tests)
  - Health Check (1 test)

---

## Performance Characteristics

### Strengths

- **Async I/O**: Non-blocking database queries
- **Indexed Lookups**: O(log n) for hostname/pattern searches
- **Lightweight**: FastAPI + SQLite minimal overhead
- **Horizontal Scaling**: Multiple instances can share read-only DB

### Limitations

- **SQLite Write Locks**: Concurrent writes not supported (read-only design)
- **In-Memory Caching**: Not implemented (consider Redis for production)
- **Pattern Matching**: Linear scan of patterns (optimize with Aho-Corasick if needed)

---

## Security Features

### Input Validation

✅ Control character removal  
✅ Port range validation (1-65535)  
✅ Scheme restriction (HTTP/HTTPS only)  
✅ URL format validation (regex)  

### Threat Detection

✅ Domain reputation lookup  
✅ SQL injection patterns  
✅ XSS attack patterns  
✅ Path traversal detection  
✅ Command injection patterns  
✅ Malware signature paths  

### Design Philosophy

- **Permissive by default**: Unknown domains return `status: 'unknown'` (not blocked)
- **Pattern-based detection**: Scans for known attack signatures
- **Layered defense**: Multiple validation stages before database lookup

---

## Deployment

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run server
python main.py
```

### Production Considerations

1. **Use production ASGI server**: `uvicorn main:app --workers 4`
2. **Enable logging**: Configure logging middleware
3. **Add rate limiting**: Prevent abuse
4. **Use PostgreSQL**: For write-heavy workloads
5. **Add caching layer**: Redis for frequent lookups
6. **Monitor performance**: Application metrics

---

## Future Enhancements

### Planned Features

- [ ] Configuration file for permissive/restrictive modes
- [ ] Redis caching layer
- [ ] Bulk URL checking endpoint
- [ ] Domain submission API (add new threats)
- [ ] Historical lookup logs
- [ ] Metrics dashboard
- [ ] Load balancer integration
- [ ] Docker containerization

---

## Project Structure

``` text
/Users/pramosba/00_httplookup/
├── main.py                    # FastAPI application
├── requirements.txt           # Python dependencies
├── Dockerfile                 # Docker configuration (empty)
├── README.md                  # Project readme
├── pytest.ini                # pytest configuration
├── databases/
│   ├── lookup.db             # SQLite database file
│   ├── schema.sql            # Database schema + demo data
│   └── SCHEMA.md             # Schema documentation
├── docs/
│   ├── development_process.md # Development journal
│   └── API.md                # This file
├── tests/
│   └── test_main.py          # Test suite (38 tests)
├── app/                      # (Future: Application modules)
├── dashboard/                # (Future: Monitoring dashboard)
├── loadbalancer/             # (Future: Load balancer config)
├── homepage/                 # (Future: Web UI)
└── docker/                   # (Future: Docker compose files)
```

---

## Version History

- **v1.0.0** (2025-12-22): Initial release with FastAPI, SQLite, and threat detection
