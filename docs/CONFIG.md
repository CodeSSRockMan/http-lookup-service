# Configuration Guide

The HTTP Lookup Service uses a YAML configuration file (`config.yaml`) for flexible deployment settings.

## Configuration File Location

The configuration file should be located at the root of the project:
```
/Users/pramosba/00_httplookup/config.yaml
```

## Configuration Options

### Server Configuration

```yaml
server:
  host: "0.0.0.0"      # Bind to all interfaces (use "127.0.0.1" for localhost only)
  port: 8000           # Server port (default: 8000)
  workers: 1           # Number of worker processes (use 1 for development)
```

**Common Port Configurations:**
- `8000` - Default, commonly used for development
- `5000` - Alternative (note: may conflict with macOS AirPlay on port 5000)
- `80` - HTTP standard (requires root/admin privileges)
- `443` - HTTPS standard (requires root/admin privileges + SSL setup)

### Database Configuration

```yaml
database:
  path: "databases/lookup.db"          # Path to SQLite database file
  schema_path: "databases/schema.sql"  # Path to database schema
```

### Security Configuration

```yaml
security:
  # Toggle malicious pattern detection
  enable_pattern_matching: true
  
  # Toggle domain reputation lookup
  enable_domain_lookup: true
  
  validation:
    # Allowed URL schemes
    allowed_schemes:
      - "http"
      - "https"
    
    # Port range validation
    min_port: 1
    max_port: 65535
    
    # Maximum URL length (prevents DoS attacks)
    max_url_length: 2048
```

**Security Options Explained:**
- `enable_pattern_matching`: When `true`, checks URLs for SQLi, XSS, path traversal, etc.
- `enable_domain_lookup`: When `true`, checks domain reputation in database
- `allowed_schemes`: List of acceptable URL schemes (http, https, ftp, etc.)
- `min_port/max_port`: Valid port range (1-65535 standard)
- `max_url_length`: Maximum allowed URL length to prevent DoS attacks

### Logging Configuration

```yaml
logging:
  level: "INFO"  # Options: DEBUG, INFO, WARNING, ERROR, CRITICAL
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
```

**Log Levels:**
- `DEBUG`: Detailed information for debugging
- `INFO`: General informational messages (recommended for production)
- `WARNING`: Warning messages for potential issues
- `ERROR`: Error messages for failures
- `CRITICAL`: Critical errors that may stop the service

### Performance Configuration

```yaml
performance:
  enable_cache: false   # Enable response caching (future enhancement)
  cache_ttl: 300        # Cache time-to-live in seconds
```

*Note: Caching is not yet implemented but configuration is ready for future enhancement.*

## Usage Examples

### Example 1: Development Configuration

```yaml
server:
  host: "127.0.0.1"  # Localhost only
  port: 8000
  workers: 1

logging:
  level: "DEBUG"  # Verbose logging for development
```

### Example 2: Production Configuration

```yaml
server:
  host: "0.0.0.0"  # All interfaces
  port: 80
  workers: 4       # Multiple workers for better performance

security:
  validation:
    max_url_length: 1024  # Stricter limit

logging:
  level: "WARNING"  # Less verbose logging
```

### Example 3: Testing Configuration (No Database Checks)

```yaml
security:
  enable_pattern_matching: false  # Disable pattern matching
  enable_domain_lookup: false     # Disable domain lookup

logging:
  level: "ERROR"  # Minimal logging
```

## Changing the Port

To change the server port, edit `config.yaml`:

```yaml
server:
  port: 3000  # Change to your desired port
```

Then restart the server:
```bash
python main.py
```

The server will log the configured port on startup:
```
2025-12-22 09:48:47,336 - __main__ - INFO - Starting server on 0.0.0.0:3000 with 1 worker(s)
```

## Configuration Validation

The application will fail to start if:
- `config.yaml` is missing
- YAML syntax is invalid
- Required fields are missing

Error example:
```
FileNotFoundError: [Errno 2] No such file or directory: 'config.yaml'
```

## Environment-Specific Configurations

You can maintain multiple configuration files for different environments:

```bash
# Development
cp config.yaml config.dev.yaml

# Production
cp config.yaml config.prod.yaml

# Testing
cp config.yaml config.test.yaml
```

Then use environment variables or command-line arguments to load the appropriate config (requires code modification).

## Best Practices

1. **Development**: Use `host: "127.0.0.1"` and `level: "DEBUG"`
2. **Production**: Use `host: "0.0.0.0"`, multiple workers, and `level: "WARNING"`
3. **Security**: Always enable `enable_pattern_matching` and `enable_domain_lookup` in production
4. **Port Selection**: Avoid port 5000 on macOS (conflicts with AirPlay)
5. **Workers**: Start with 1 worker and increase based on load (CPU cores * 2 is a good rule)

## Troubleshooting

### Port Already in Use
```
Error: [Errno 48] Address already in use
```
**Solution**: Change the port in `config.yaml` or kill the process using that port:
```bash
lsof -i :8000
kill -9 <PID>
```

### Permission Denied (Ports < 1024)
```
Error: [Errno 13] Permission denied
```
**Solution**: Ports below 1024 require root privileges:
```bash
sudo python main.py
```

### YAML Parse Error
```
Error: yaml.scanner.ScannerError
```
**Solution**: Check YAML syntax - ensure proper indentation (use spaces, not tabs)

---

**Last Updated:** 2025-12-22  
**Configuration Version:** 1.0.0
