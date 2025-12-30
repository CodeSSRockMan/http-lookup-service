# Database Schema Documentation

This document describes the database structure used by the HTTP Lookup Service.

## Overview

The service uses **SQLite** for storing domain reputation data and malicious pattern signatures. The database is automatically initialized on first startup using `databases/schema.sql`.

**Database Location:** `databases/lookup.db`

---

## Tables

### 1. `domains` Table

Stores domain reputation information for known hosts.

#### Schema

```sql
CREATE TABLE domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname VARCHAR(255) NOT NULL UNIQUE,
    status VARCHAR(50) NOT NULL,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Columns

| Column | Type | Constraints | Description |
| ------ | ---- | ----------- | ----------- |
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique identifier |
| `hostname` | VARCHAR(255) | NOT NULL, UNIQUE | Domain name (e.g., `example.com`) |
| `status` | VARCHAR(50) | NOT NULL, CHECK constraint | Domain reputation status |
| `last_updated` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Last update timestamp |
| `description` | TEXT | - | Human-readable description |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Record creation timestamp |

#### Status Values

The `status` column accepts only these values:

- **`safe`** - Verified safe domain (trusted sites)
- **`malicious`** - Known malware distribution or harmful site
- **`phishing`** - Phishing or impersonation attempt
- **`blacklisted`** - Spam or otherwise blocked domain

#### Indexes

```sql
CREATE INDEX idx_hostname ON domains(hostname);  -- Fast lookups
CREATE INDEX idx_status ON domains(status);      -- Status filtering
```

#### Example Data

```sql
INSERT INTO domains (hostname, status, description) VALUES
    ('example.com', 'safe', 'Example domain - safe for testing'),
    ('malicious-site.com', 'malicious', 'Known malware distribution site'),
    ('phishing-bank.com', 'phishing', 'Fake banking site');
```

---

### 2. `malicious_queries` Table

Stores patterns for detecting malicious URL components (paths, query parameters).

#### Schema

```sql
CREATE TABLE malicious_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT NOT NULL UNIQUE,
    pattern_type VARCHAR(50) NOT NULL,
    threat_type VARCHAR(50) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### Columns

| Column | Type | Constraints | Description |
| ------ | ---- | ----------- | ----------- |
| `id` | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique identifier |
| `pattern` | TEXT | NOT NULL, UNIQUE | Malicious pattern to detect |
| `pattern_type` | VARCHAR(50) | NOT NULL, CHECK constraint | Where the pattern appears |
| `threat_type` | VARCHAR(50) | NOT NULL, CHECK constraint | Type of attack |
| `description` | TEXT | - | Pattern description |
| `created_at` | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Record creation timestamp |

#### Pattern Types

The `pattern_type` column indicates where the pattern is detected:

- **`path`** - URL path component (e.g., `../`, `/shell.php`)
- **`query_param`** - Query string parameters (e.g., `?id=1' OR 1=1`)
- **`full_pattern`** - Full URL pattern match

#### Threat Types

The `threat_type` column categorizes the attack:

- **`sql_injection`** - SQL injection attempts
- **`xss`** - Cross-Site Scripting attacks
- **`path_traversal`** - Directory traversal attempts
- **`command_injection`** - OS command injection
- **`malware`** - Malware-related patterns

#### Indexes

```sql
CREATE INDEX idx_pattern ON malicious_queries(pattern);          -- Fast lookups
CREATE INDEX idx_threat_type ON malicious_queries(threat_type);  -- Threat filtering
```

#### Example Data

```sql
INSERT INTO malicious_queries (pattern, pattern_type, threat_type, description) VALUES
    ('../', 'path', 'path_traversal', 'Directory traversal pattern'),
    ('SELECT * FROM', 'query_param', 'sql_injection', 'SQL injection attempt'),
    ('<script>', 'query_param', 'xss', 'XSS script tag injection'),
    ('/shell.php', 'path', 'malware', 'Web shell upload');
```

---

## Database Initialization

The database is automatically initialized when the server starts if it doesn't exist:

```python
async def init_database():
    """Initialize the database with schema"""
    schema_path = os.path.join(os.path.dirname(__file__), config['database']['schema_path'])
    async with aiosqlite.connect(DB_PATH) as db:
        with open(schema_path, 'r') as f:
            schema = f.read()
        await db.executescript(schema)
        await db.commit()
```

**Configuration** (`config.yaml`):

```yaml
database:
  path: 'databases/lookup.db'
  schema_path: 'databases/schema.sql'
```

---

## Demo Data

The schema includes demo data for testing:

### Demo Domains

- **Safe:** `example.com`, `google.com`, `github.com`
- **Malicious:** `malicious-site.com`, `evil-download.org`
- **Phishing:** `phishing-bank.com`, `fake-paypal.com`
- **Blacklisted:** `spam-domain.net`

### Demo Patterns (19 total)

- **SQL Injection:** `SELECT * FROM`, `DROP TABLE`, `' OR 1=1`, `UNION SELECT`
- **XSS:** `<script>`, `javascript:`, `<iframe>`, `onerror=`
- **Path Traversal:** `../`, `..\\`, `%2e%2e%2f`, `../../../etc/passwd`
- **Command Injection:** `eval(`, `| cat /etc/passwd`, `${`
- **Malware:** `/wp-admin/install.php`, `/shell.php`

---

## Querying the Database

### Domain Lookup Example

```python
async def lookup_domain(hostname):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT hostname, status, description, last_updated FROM domains WHERE hostname = ?",
            (hostname,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return {
                    'hostname': row['hostname'],
                    'status': row['status'],
                    'description': row['description'],
                    'last_updated': row['last_updated']
                }
    return None
```

### Pattern Matching Example

```python
async def check_malicious_patterns(url):
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT pattern, pattern_type, threat_type, description FROM malicious_queries"
        ) as cursor:
            async for row in cursor:
                pattern = row['pattern']
                if pattern.lower() in url.lower():
                    return {
                        'pattern': row['pattern'],
                        'pattern_type': row['pattern_type'],
                        'threat_type': row['threat_type'],
                        'description': row['description']
                    }
    return None
```

---

## Performance Considerations

### Indexes

Both tables have indexes on frequently queried columns:
- `domains.hostname` - Used in every URL check
- `domains.status` - Used for filtering by reputation
- `malicious_queries.pattern` - Used in pattern matching
- `malicious_queries.threat_type` - Used for threat analysis

### Query Optimization

- **Domain lookups** are O(log n) due to index on hostname
- **Pattern matching** iterates all patterns - consider adding a trie or regex index for larger datasets
- **Connection pooling** via `aiosqlite` for async operations

### Scaling Recommendations

For production use with large datasets:

1. **Add more indexes** if filtering by other columns
2. **Use PostgreSQL** for better concurrent write performance
3. **Implement caching** (Redis) for frequently accessed domains
4. **Pre-compile regex patterns** for faster matching
5. **Partition patterns** by threat_type for targeted scanning

---

## Maintenance

### Backup

```bash
# Backup database
cp databases/lookup.db databases/lookup.db.backup

# Restore from backup
cp databases/lookup.db.backup databases/lookup.db
```

### Reset Database

```bash
# Remove database
rm databases/lookup.db

# Restart server (will reinitialize)
./stop_server.sh
./start_server.sh
```

### Update Patterns

```sql
-- Add new malicious pattern
INSERT INTO malicious_queries (pattern, pattern_type, threat_type, description)
VALUES ('rm -rf /', 'query_param', 'command_injection', 'Dangerous delete command');

-- Update domain status
UPDATE domains SET status = 'malicious', last_updated = CURRENT_TIMESTAMP
WHERE hostname = 'newly-malicious.com';
```

---

## Security Notes

1. **Input Validation:** All queries use parameterized statements to prevent SQL injection
2. **Read-Only:** Current implementation only reads from database (no user-generated writes)
3. **Pattern Matching:** Case-insensitive substring matching (consider regex for complex patterns)
4. **Demo Data:** Replace demo data with real threat intelligence in production

---

## See Also

- [SECURITY.md](SECURITY.md) - Security pipeline and validation order
- [API.md](API.md) - API documentation and usage examples
- [CONFIG.md](CONFIG.md) - Configuration guide
