from flask import Flask, jsonify
from urllib.parse import unquote, unquote_plus, urlparse
import re

app = Flask(__name__)


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


@app.route('/urlinfo/1/<path:url_parts>', methods=['GET'])
def check_url(url_parts):
    """
    Endpoint to check URL information.
    Format: /urlinfo/1/{hostname_and_port}/{original_path_and_query_string}
    
    Args:
        url_parts: The full path containing hostname_and_port and original_path_and_query_string
    """
    try:
        # Split the url_parts to extract hostname_and_port
        parts = url_parts.split('/', 1)
        
        if len(parts) < 1:
            return jsonify({
                'error': 'Invalid URL format',
                'message': 'Expected format: /urlinfo/1/{hostname_and_port}/{original_path_and_query_string}'
            }), 400
        
        hostname_and_port = parts[0]
        original_path_and_query = parts[1] if len(parts) > 1 else ''
        
        # Reconstruct the full URL (assuming http by default)
        if hostname_and_port.startswith(('http://', 'https://')):
            reconstructed_url = f"{hostname_and_port}/{original_path_and_query}" if original_path_and_query else hostname_and_port
        else:
            reconstructed_url = f"http://{hostname_and_port}/{original_path_and_query}" if original_path_and_query else f"http://{hostname_and_port}"
        
        # Sanitize the URL
        sanitized_url = sanitize_url(reconstructed_url)
        
        # Decode URL-encoded characters
        decoded_url = decode_url_parts(sanitized_url)
        
        # Validate using regex
        if not validate_url_regex(decoded_url):
            return jsonify({
                'error': 'Invalid HTTP URL',
                'message': 'URL does not match valid HTTP/HTTPS format',
                'url': decoded_url
            }), 400
        
        return jsonify({
            'valid': True,
            'url': decoded_url
        }), 200
        
    except Exception as e:
        return jsonify({
            'error': 'Processing error',
            'message': str(e)
        }), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy'}), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
