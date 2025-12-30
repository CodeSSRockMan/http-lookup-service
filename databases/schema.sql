-- HTTP Lookup Service Database Schema

CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname VARCHAR(255) NOT NULL UNIQUE,
    status VARCHAR(50) NOT NULL CHECK(status IN ('safe', 'blacklisted', 'malicious', 'phishing')),
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index on hostname for fast lookups
CREATE INDEX IF NOT EXISTS idx_hostname ON domains(hostname);

-- Create index on status for filtering
CREATE INDEX IF NOT EXISTS idx_status ON domains(status);

-- Table for malicious query patterns
CREATE TABLE IF NOT EXISTS malicious_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern TEXT NOT NULL UNIQUE,
    pattern_type VARCHAR(50) NOT NULL CHECK(pattern_type IN ('path', 'query_param', 'full_pattern')),
    threat_type VARCHAR(50) NOT NULL CHECK(threat_type IN ('sql_injection', 'xss', 'path_traversal', 'command_injection', 'malware')),
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index on pattern for fast lookups
CREATE INDEX IF NOT EXISTS idx_pattern ON malicious_queries(pattern);

-- Create index on threat_type for filtering
CREATE INDEX IF NOT EXISTS idx_threat_type ON malicious_queries(threat_type);

-- Insert demo data
INSERT OR IGNORE INTO domains (hostname, status, description) VALUES
    ('example.com', 'safe', 'Example domain - safe for testing'),
    ('google.com', 'safe', 'Google search engine'),
    ('github.com', 'safe', 'GitHub code repository'),
    ('malicious-site.com', 'malicious', 'Known malware distribution site'),
    ('phishing-bank.com', 'phishing', 'Fake banking site'),
    ('spam-domain.net', 'blacklisted', 'Spam and advertising site'),
    ('evil-download.org', 'malicious', 'Malware download site'),
    ('fake-paypal.com', 'phishing', 'PayPal phishing attempt');

-- Insert demo malicious query patterns
INSERT OR IGNORE INTO malicious_queries (pattern, pattern_type, threat_type, description) VALUES
    ('SELECT * FROM', 'query_param', 'sql_injection', 'SQL injection attempt'),
    ('DROP TABLE', 'query_param', 'sql_injection', 'SQL DROP TABLE injection'),
    ('../../../etc/passwd', 'path', 'path_traversal', 'Path traversal to system files'),
    ('../', 'path', 'path_traversal', 'Directory traversal pattern'),
    ('<script>', 'query_param', 'xss', 'XSS script tag injection'),
    ('javascript:', 'query_param', 'xss', 'JavaScript protocol XSS'),
    ('eval(', 'query_param', 'command_injection', 'JavaScript eval injection'),
    ('/wp-admin/install.php', 'path', 'malware', 'WordPress vulnerability scan'),
    ('/shell.php', 'path', 'malware', 'Web shell upload'),
    ('| cat /etc/passwd', 'query_param', 'command_injection', 'Command injection with pipe'),
    (''' OR 1=1''', 'query_param', 'sql_injection', 'SQL injection attempt'),
    (''' OR ''1''=''1', 'query_param', 'sql_injection', 'SQL injection boolean bypass'),
    ('UNION SELECT', 'query_param', 'sql_injection', 'SQL UNION injection'),
    ('--', 'query_param', 'sql_injection', 'SQL comment injection'),
    ('<iframe>', 'query_param', 'xss', 'XSS iframe injection'),
    ('onerror=', 'query_param', 'xss', 'XSS event handler injection'),
    ('..\\', 'path', 'path_traversal', 'Windows path traversal'),
    ('%2e%2e%2f', 'path', 'path_traversal', 'URL-encoded path traversal'),
    ('${', 'query_param', 'command_injection', 'Template injection');

