# Development Process Journal

## Step 1: Requirements and Scoping

- Read through the project requirements
- Scoped resources needed for the project

## Step 2: Initialize Git Project

- Initialized git repository with an easy-to-read structure
- Created organized folder structure for better maintainability
- Enabled version control for the project

## Step 3: Initialize Basic Flask Server

- Set up Flask server to handle GET requests
- Created endpoint: `/urlinfo/1/{hostname_and_port}/{original_path_and_query_string}`
- Implemented validation functions:
  - `is_valid_scheme()` - validates HTTP/HTTPS scheme
  - `is_valid_hostname()` - validates hostname exists
  - `is_valid_port()` - validates port range (1-65535)
  - `validate_url_stages()` - orchestrates validation in stages

## Step 4: Migrate to FastAPI

- Migrated from Flask to FastAPI for improved performance
- FastAPI provides async support and better speed for URL lookup operations
- Maintained all validation logic:
  - URL sanitization (removes control characters)
  - URL decoding with `unquote()` for host/path and `unquote_plus()` for queries
  - Regex validation for HTTP/HTTPS URLs
  - Port range validation (1-65535)
- Added comprehensive pytest test suite (29 tests)
- All tests passing successfully

## Step 5: Database Integration

- Created SQLite database schema with indexed domains table
- Table tracks hostname, status (safe/blacklisted/malicious/phishing), and metadata
- Implemented async database lookup with aiosqlite
- Integrated lookup into main endpoint - returns domain threat status
- Added demo data for testing (8 sample domains)
- Extended test suite to 34 tests covering database lookups
- Database is read-only, suitable for multiple process instances

## Step 6: Malicious Pattern Detection

- Added `malicious_queries` table to database schema
- Created comprehensive attack pattern library covering:
  - SQL Injection (e.g., `' OR 1=1`, `UNION SELECT`)
  - Cross-Site Scripting (e.g., `<script>`, `javascript:`)
  - Path Traversal (e.g., `../`, `..\\`)
  - Command Injection (e.g., `; rm -rf`, `| cat`)
- Implemented async pattern matching against database
- Added 4 new tests for malicious pattern detection
- Extended test suite to 38 tests total
- All tests passing successfully

## Step 7: Security Pipeline Review & Documentation

- **Critical Security Issue Identified**: Order of operations in validation pipeline
- **Problem**: If URL decoding happens after validation/pattern matching, encoded attacks can bypass detection
- **Example**: `%27OR%201%3D1` (encoded SQL injection) looks harmless until decoded to `'OR 1=1`

### Correct Order Established:
1. **DECODE FIRST** - Convert URL-encoded chars to actual values (`%27` → `'`)
2. **VALIDATE** - Check URL format and structure
3. **PATTERN MATCH** - Check decoded content for known attacks
4. **SANITIZE** - Remove control characters (defensive measure)
5. **DATABASE LOOKUP** - Check domain reputation

### Why This Order Matters:
- Decoding must happen **before** validation to prevent encoding-based bypass attacks
- Pattern matching must check **decoded** content to detect encoded attacks
- Sanitization is a last-resort cleanup, not a security measure
- Database lookup happens last after all validation checks

### Documentation Created:
- Created comprehensive security documentation: `docs/SECURITY.md`
- Documents the 5-step security pipeline with detailed explanations
- Includes attack prevention examples and real-world scenarios
- Explains why order matters with side-by-side comparisons
- Lists known limitations and future enhancements
- Added ASCII diagram of security pipeline flow

### Code Quality:
- Enhanced inline comments in `main.py` to explain each step
- Comments now include "WHY" explanations for security decisions
- All 38 tests still passing after documentation updates
- Code review confirms correct order of operations

## Project Complete

All requirements met:
- ✅ High-performance async FastAPI service
- ✅ Comprehensive URL validation (decode → validate → pattern match → sanitize → DB lookup)
- ✅ Database-backed domain reputation checks
- ✅ Malicious pattern detection (SQLi, XSS, path traversal, etc.)
- ✅ 38 comprehensive tests covering all functionality
- ✅ Detailed documentation (API, security, schema, development process)
- ✅ Production-ready security architecture

Ready for deployment or further enhancements (Redis caching, Dockerization, etc.)
