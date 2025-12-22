from fastapi import FastAPI, Path, HTTPException
from fastapi.responses import JSONResponse
from urllib.parse import unquote, unquote_plus, urlparse
import re

app = FastAPI(title="HTTP Lookup Service", version="1.0.0")


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
async def check_url(url_parts: str = Path(..., description="Full path with hostname_and_port/original_path_and_query_string")):
    """
    Endpoint to check URL information.
    Format: /urlinfo/1/{hostname_and_port}/{original_path_and_query_string}
    
    Args:
        url_parts: The full path containing hostname_and_port and original_path_and_query_string
    """
    try:
        # Check if url_parts starts with http:// or https://
        if url_parts.startswith('http://') or url_parts.startswith('https://'):
            # URL already has scheme, use it directly
            reconstructed_url = url_parts
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
        
        # Sanitize the URL
        sanitized_url = sanitize_url(reconstructed_url)
        
        # Decode URL-encoded characters
        decoded_url = decode_url_parts(sanitized_url)
        
        # Validate using regex
        if not validate_url_regex(decoded_url):
            raise HTTPException(
                status_code=400,
                detail={
                    'error': 'Invalid HTTP URL',
                    'message': 'URL does not match valid HTTP/HTTPS format',
                    'url': decoded_url
                }
            )
        
        return {
            'valid': True,
            'url': decoded_url
        }
        
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
    uvicorn.run(app, host='0.0.0.0', port=5000)
