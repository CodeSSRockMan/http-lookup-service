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
