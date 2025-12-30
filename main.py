from fastapi import FastAPI, Path, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from urllib.parse import unquote, unquote_plus, urlparse
from contextlib import asynccontextmanager
import re
import aiosqlite
import os
import yaml
import logging
from datetime import datetime

# Load configuration
def load_config():
    """Load configuration from YAML file"""
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

config = load_config()

# Setup logging
logging.basicConfig(
    level=getattr(logging, config['logging']['level']),
    format=config['logging']['format']
)
logger = logging.getLogger(__name__)

# Database path from config
DB_PATH = os.path.join(os.path.dirname(__file__), config['database']['path'])


async def init_database():
    """Initialize the database with schema"""
    schema_path = os.path.join(os.path.dirname(__file__), config['database']['schema_path'])
    logger.info(f"Initializing database at {DB_PATH}")
    async with aiosqlite.connect(DB_PATH) as db:
        with open(schema_path, 'r') as f:
            schema = f.read()
        await db.executescript(schema)
        await db.commit()
    logger.info("Database initialized successfully")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown events"""
    logger.info("Starting HTTP Lookup Service...")
    await init_database()
    logger.info(f"Server configuration: {config['server']}")
    yield
    logger.info("Shutting down HTTP Lookup Service...")

app = FastAPI(title="HTTP Lookup Service", version="1.0.0", lifespan=lifespan)

# Mount static files if frontend is enabled
if config.get('frontend', {}).get('enabled', True):
    static_dir = os.path.join(os.path.dirname(__file__), config['frontend']['static_dir'])
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# In-memory statistics storage (replace with database in production)
stats = {
    'total_checks': 0,
    'safe_urls': 0,
    'threats_detected': 0,
    'unknown_domains': 0,
    'recent_checks': []
}


async def lookup_domain(hostname):
    """
    Lookup domain status in database.
    Respects configuration setting for domain lookup.
    
    Args:
        hostname: The hostname to lookup
        
    Returns:
        dict: Domain information or None if not found
    """
    # Check if domain lookup is enabled in config
    if not config['security']['enable_domain_lookup']:
        return None
    
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


async def check_malicious_patterns(url):
    """
    Check URL path and query for malicious patterns.
    Respects configuration setting for pattern matching.
    
    Args:
        url: The full URL to check
        
    Returns:
        dict: Malicious pattern information or None if clean
    """
    # Check if pattern matching is enabled in config
    if not config['security']['enable_pattern_matching']:
        return None
    
    parsed = urlparse(url)
    full_url = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path
    
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT pattern, pattern_type, threat_type, description FROM malicious_queries"
        ) as cursor:
            async for row in cursor:
                pattern = row['pattern']
                # Check if pattern exists in URL (case-insensitive)
                if pattern.lower() in full_url.lower():
                    return {
                        'pattern': row['pattern'],
                        'pattern_type': row['pattern_type'],
                        'threat_type': row['threat_type'],
                        'description': row['description']
                    }
    return None


def sanitize_url(url):
    """
    Sanitizes the URL by removing potentially harmful characters.
    
    Args:
        url: The URL string to sanitize
        
    Returns:
        str: Sanitized URL
    """
    # Remove leading/trailing whitespace
    url = url.strip()
    
    # Remove null bytes and other control characters
    url = re.sub(r'[\x00-\x1f\x7f]', '', url)
    
    return url


def decode_url_parts(url):
    """
    Decodes URL-encoded characters from URL components.
    Uses unquote for host/path and unquote_plus for query strings.
    
    Args:
        url: The URL string to decode
        
    Returns:
        str: Decoded URL
    """
    try:
        parsed = urlparse(url)
        
        # Decode host part with unquote
        decoded_netloc = unquote(parsed.netloc) if parsed.netloc else ''
        
        # Decode path with unquote
        decoded_path = unquote(parsed.path) if parsed.path else ''
        
        # Decode query with unquote_plus (handles + as space)
        decoded_query = unquote_plus(parsed.query) if parsed.query else ''
        
        # Reconstruct URL
        scheme = parsed.scheme
        query_part = f"?{decoded_query}" if decoded_query else ''
        
        decoded_url = f"{scheme}://{decoded_netloc}{decoded_path}{query_part}"
        
        return decoded_url
        
    except Exception:
        return url


def validate_url_regex(url):
    """
    Validates URL using regex pattern for HTTP/HTTPS URLs.
    Uses allowed schemes from configuration.
    
    Args:
        url: The URL string to validate
        
    Returns:
        bool: True if URL matches HTTP/HTTPS pattern, False otherwise
    """
    # Get allowed schemes from config
    allowed_schemes = config['security']['validation']['allowed_schemes']
    schemes_pattern = '|'.join(allowed_schemes)
    
    # HTTP/HTTPS URL regex pattern
    pattern = f'^({schemes_pattern})://[a-zA-Z0-9]([a-zA-Z0-9\\-]{{0,61}}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{{0,61}}[a-zA-Z0-9])?)*(:[0-9]{{1,5}})?(/.*)?$'
    
    if not re.match(pattern, url):
        return False
    
    # Additional validation: check port range if present
    min_port = config['security']['validation']['min_port']
    max_port = config['security']['validation']['max_port']
    
    try:
        parsed = urlparse(url)
        if parsed.port is not None:
            if parsed.port < min_port or parsed.port > max_port:
                return False
    except ValueError:
        # Invalid port format
        return False
    
    # Check maximum URL length
    max_length = config['security']['validation']['max_url_length']
    if len(url) > max_length:
        return False
    
    return True


@app.get("/urlinfo/1/{url_parts:path}")
async def check_url(url_parts: str = Path(..., description="Full path with hostname_and_port/original_path_and_query_string"), request: Request = None):
    """
    Endpoint to check URL information.
    Format: /urlinfo/1/{hostname_and_port}/{original_path_and_query_string}
    
    Args:
        url_parts: The full path containing hostname_and_port and original_path_and_query_string
        request: FastAPI Request object to get query string
    """
    try:
        # Get query string if present
        query_string = request.url.query if request and request.url.query else ''
        
        # Check if url_parts starts with http:// or https://
        if url_parts.startswith('http://') or url_parts.startswith('https://'):
            # URL already has scheme, use it directly
            reconstructed_url = url_parts
            if query_string:
                reconstructed_url = f"{reconstructed_url}?{query_string}"
        else:
            # Split the url_parts to extract hostname_and_port
            parts = url_parts.split('/', 1)
            
            if len(parts) < 1:
                raise HTTPException(
                    status_code=400,
                    detail={
                        'error': 'Invalid URL format',
                        'message': 'Expected format: /urlinfo/1/{hostname_and_port}/{original_path_and_query_string}'
                    }
                )
            
            hostname_and_port = parts[0]
            original_path_and_query = parts[1] if len(parts) > 1 else ''
            
            # Reconstruct the full URL (assuming http by default)
            reconstructed_url = f"http://{hostname_and_port}/{original_path_and_query}" if original_path_and_query else f"http://{hostname_and_port}"
            if query_string:
                reconstructed_url = f"{reconstructed_url}?{query_string}"
        
        # SECURITY PIPELINE ORDER (CRITICAL FOR PREVENTING BYPASS ATTACKS):
        # =====================================================================
        # STEP 1: DECODE FIRST - Convert URL-encoded chars to actual values
        #         WHY: Attackers can encode malicious chars like %27 (') or %3C (<)
        #              to bypass regex/pattern matching. MUST decode before validation.
        decoded_url = decode_url_parts(reconstructed_url)
        
        # STEP 2: VALIDATE FORMAT - Check if it's a valid HTTP/HTTPS URL structure
        #         WHY: No point in further processing if URL format is invalid.
        if not validate_url_regex(decoded_url):
            raise HTTPException(
                status_code=400,
                detail={
                    'error': 'Invalid HTTP URL',
                    'message': 'URL does not match valid HTTP/HTTPS format',
                    'url': decoded_url
                }
            )
        
        # STEP 3: PATTERN MATCH - Check decoded content for malicious patterns
        #         WHY: Must check the actual decoded chars to detect SQLi, XSS, etc.
        #              Encoded attacks like %27OR%201%3D1 would bypass if not decoded first.
        malicious_info = await check_malicious_patterns(decoded_url)
        
        # STEP 4: SANITIZE - Remove control characters as a safety measure
        #         WHY: Last-resort cleanup for edge cases. Not for security (already validated).
        sanitized_url = sanitize_url(decoded_url)
        
        # STEP 5: DATABASE LOOKUP - Check domain reputation in database
        #         WHY: After all validation/pattern checks, look up the domain's reputation.
        # Extract hostname for database lookup
        parsed = urlparse(sanitized_url)
        hostname = parsed.hostname
        
        # Lookup domain in database
        domain_info = await lookup_domain(hostname)
        
        if domain_info:
            result = {
                'valid': True,
                'url': sanitized_url,
                'lookup_result': {
                    'found': True,
                    'hostname': domain_info['hostname'],
                    'status': domain_info['status'],
                    'description': domain_info['description'],
                    'last_updated': domain_info['last_updated']
                }
            }
        else:
            result = {
                'valid': True,
                'url': sanitized_url,
                'lookup_result': {
                    'found': False,
                    'hostname': hostname,
                    'status': 'unknown',
                    'message': 'Domain not found in database'
                }
            }
        
        # If malicious patterns found, add to result
        if malicious_info:
            result['malicious_patterns'] = {
                'found': True,
                'pattern': malicious_info['pattern'],
                'pattern_type': malicious_info['pattern_type'],
                'threat_type': malicious_info['threat_type'],
                'description': malicious_info['description']
            }
        else:
            result['malicious_patterns'] = {
                'found': False
            }
        
        # Update statistics
        stats['total_checks'] += 1
        if malicious_info:
            stats['threats_detected'] += 1
        elif domain_info and domain_info['status'] == 'safe':
            stats['safe_urls'] += 1
        elif not domain_info:
            stats['unknown_domains'] += 1
        
        # Store recent check (keep last 10)
        stats['recent_checks'].insert(0, {
            'url': sanitized_url,
            'status': 'threat' if malicious_info else (domain_info['status'] if domain_info else 'unknown'),
            'timestamp': datetime.now().isoformat()
        })
        stats['recent_checks'] = stats['recent_checks'][:10]
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                'error': 'Processing error',
                'message': str(e)
            }
        )


# Frontend Routes
@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def home():
    """Serve the main search page"""
    if not config.get('frontend', {}).get('enabled', True):
        return JSONResponse({"message": "Frontend is disabled"}, status_code=404)
    
    static_dir = os.path.join(os.path.dirname(__file__), config['frontend']['static_dir'])
    index_path = os.path.join(static_dir, 'index.html')
    return FileResponse(index_path)


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard():
    """Serve the dashboard page"""
    if not config.get('frontend', {}).get('enabled', True):
        return JSONResponse({"message": "Frontend is disabled"}, status_code=404)
    
    static_dir = os.path.join(os.path.dirname(__file__), config['frontend']['static_dir'])
    dashboard_path = os.path.join(static_dir, 'dashboard.html')
    return FileResponse(dashboard_path)


# API Endpoints for Dashboard
@app.get("/api/stats")
async def get_stats():
    """Get service statistics"""
    # Get database counts
    async with aiosqlite.connect(DB_PATH) as db:
        # Count known domains
        async with db.execute("SELECT COUNT(*) FROM domains") as cursor:
            row = await cursor.fetchone()
            known_domains = row[0] if row else 0
        
        # Count malicious patterns
        async with db.execute("SELECT COUNT(*) FROM malicious_queries") as cursor:
            row = await cursor.fetchone()
            malicious_patterns = row[0] if row else 0
    
    return {
        'total_checks': stats['total_checks'],
        'safe_urls': stats['safe_urls'],
        'threats_detected': stats['threats_detected'],
        'unknown_domains': stats['unknown_domains'],
        'known_domains': known_domains,
        'malicious_patterns': malicious_patterns,
        'pattern_matching_enabled': config['security']['enable_pattern_matching'],
        'domain_lookup_enabled': config['security']['enable_domain_lookup']
    }


@app.get("/api/recent-checks")
async def get_recent_checks():
    """Get recent URL checks"""
    return {
        'checks': stats['recent_checks']
    }


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {'status': 'healthy'}


if __name__ == '__main__':
    import uvicorn
    
    # Get server configuration from config file
    host = config['server']['host']
    port = config['server']['port']
    workers = config['server']['workers']
    
    logger.info(f"Starting server on {host}:{port} with {workers} worker(s)")
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        workers=workers
    )
