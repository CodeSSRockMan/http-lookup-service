from fastapi import FastAPI, Path, HTTPException, Request
from fastapi.responses import JSONResponse
from urllib.parse import unquote, unquote_plus, urlparse
from contextlib import asynccontextmanager
import re
import aiosqlite
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "databases", "lookup.db")


async def init_database():
    """Initialize the database with schema"""
    async with aiosqlite.connect(DB_PATH) as db:
        schema_path = os.path.join(os.path.dirname(__file__), "databases", "schema.sql")
        with open(schema_path, 'r') as f:
            schema = f.read()
        await db.executescript(schema)
        await db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown events"""
    await init_database()
    yield

app = FastAPI(title="HTTP Lookup Service", version="1.0.0", lifespan=lifespan)


async def lookup_domain(hostname):
    """
    Lookup domain status in database.
    
    Args:
        hostname: The hostname to lookup
        
    Returns:
        dict: Domain information or None if not found
    """
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
    
    Args:
        url: The full URL to check
        
    Returns:
        dict: Malicious pattern information or None if clean
    """
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
    
    Args:
        url: The URL string to validate
        
    Returns:
        bool: True if URL matches HTTP/HTTPS pattern, False otherwise
    """
    # HTTP/HTTPS URL regex pattern
    pattern = r'^https?://[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*(:[0-9]{1,5})?(/.*)?$'
    
    if not re.match(pattern, url):
        return False
    
    # Additional validation: check port range if present
    try:
        parsed = urlparse(url)
        if parsed.port is not None:
            if parsed.port < 1 or parsed.port > 65535:
                return False
    except ValueError:
        # Invalid port format
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


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {'status': 'healthy'}


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8000)
