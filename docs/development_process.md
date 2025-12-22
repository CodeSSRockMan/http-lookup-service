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
