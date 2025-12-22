# Database Schema Documentation

## Tables

### domains

Stores information about known domains and their security status.

| Column | Type | Constraints | Description |
| -------- | ------ | ------------- | ------------- |
| id | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique identifier |
| hostname | VARCHAR(255) | NOT NULL, UNIQUE | Domain hostname (e.g., example.com) |
| status | VARCHAR(50) | NOT NULL, CHECK | Security status: 'safe', 'blacklisted', 'malicious', 'phishing' |
| last_updated | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Last time record was updated |
| description | TEXT | | Additional information about the domain |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Record creation timestamp |

**Indexes:**

- `idx_hostname` on `hostname` - Fast domain lookups
- `idx_status` on `status` - Filter by security status

---

### malicious_queries

Stores patterns of malicious URL paths and query parameters.

| Column | Type | Constraints | Description |
| -------- | ------ | ------------- | ------------- |
| id | INTEGER | PRIMARY KEY, AUTOINCREMENT | Unique identifier |
| pattern | TEXT | NOT NULL, UNIQUE | Malicious pattern to detect (e.g., "SELECT * FROM") |
| pattern_type | VARCHAR(50) | NOT NULL, CHECK | Type: 'path', 'query_param', 'full_pattern' |
| threat_type | VARCHAR(50) | NOT NULL, CHECK | Threat category: 'sql_injection', 'xss', 'path_traversal', 'command_injection', 'malware' |
| description | TEXT | | Description of the threat |
| created_at | TIMESTAMP | DEFAULT CURRENT_TIMESTAMP | Record creation timestamp |

**Indexes:**

- `idx_pattern` on `pattern` - Fast pattern matching
- `idx_threat_type` on `threat_type` - Filter by threat type

---

## Relationships

``` text
┌─────────────────────────────────────────────────────────────┐
│                     HTTP LOOKUP SERVICE                      │
│                        DATABASE SCHEMA                        │
└─────────────────────────────────────────────────────────────┘

┌───────────────────────────────┐
│         domains               │
├───────────────────────────────┤
│ id              INTEGER PK    │
│ hostname        VARCHAR(255)  │ ← UNIQUE INDEX
│ status          VARCHAR(50)   │ ← INDEX
│ last_updated    TIMESTAMP     │
│ description     TEXT          │
│ created_at      TIMESTAMP     │
└───────────────────────────────┘
        │
        │ Used for hostname reputation lookup
        ▼
   [Lookup Result]
        │
        └─→ Returns: safe | blacklisted | malicious | phishing | unknown


┌───────────────────────────────┐
│    malicious_queries          │
├───────────────────────────────┤
│ id              INTEGER PK    │
│ pattern         TEXT          │ ← UNIQUE INDEX
│ pattern_type    VARCHAR(50)   │
│ threat_type     VARCHAR(50)   │ ← INDEX
│ description     TEXT          │
│ created_at      TIMESTAMP     │
└───────────────────────────────┘
        │
        │ Used for URL path/query pattern matching
        ▼
   [Pattern Match]
        │
        └─→ Detects: SQL injection | XSS | Path traversal | Command injection | Malware
```

---

## Data Flow

1. **Incoming URL** → Sanitize → Decode → Validate format
2. **Extract hostname** → Query `domains` table
3. **Extract path/query** → Match against `malicious_queries` patterns
4. **Return combined result** with both domain reputation and threat pattern detection

---

## Demo Data

### Domains (8 entries)

- **Safe**: example.com, google.com, github.com
- **Malicious**: malicious-site.com, evil-download.org
- **Phishing**: phishing-bank.com, fake-paypal.com
- **Blacklisted**: spam-domain.net

### Malicious Queries (10 entries)

- **SQL Injection**: "SELECT * FROM", "DROP TABLE"
- **XSS**: "`<script>`", "javascript:"
- **Path Traversal**: "../../../etc/passwd", "../"
- **Command Injection**: "eval(", "| cat /etc/passwd"
- **Malware**: "/wp-admin/install.php", "/shell.php"
