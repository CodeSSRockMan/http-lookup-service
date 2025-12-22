import pytest
import sys
from pathlib import Path
import warnings

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from main import app, sanitize_url, decode_url_parts, validate_url_regex, init_database
import asyncio

# Filter out the httpx deprecation warning (false positive for ASGI apps)
warnings.filterwarnings("ignore", category=DeprecationWarning, module="httpx")

# Initialize database before tests
asyncio.run(init_database())

client = TestClient(app)


class TestSanitizeUrl:
    """Test URL sanitization function"""
    
    def test_removes_whitespace(self):
        assert sanitize_url("  http://example.com  ") == "http://example.com"
    
    def test_removes_null_bytes(self):
        result = sanitize_url("http://example.com\x00/path")
        assert "\x00" not in result
    
    def test_removes_control_characters(self):
        result = sanitize_url("http://example.com\x01\x02\x1f")
        assert result == "http://example.com"


class TestDecodeUrlParts:
    """Test URL decoding function"""
    
    def test_decode_spaces_in_path(self):
        result = decode_url_parts("http://example.com/path%20with%20spaces")
        assert "path with spaces" in result
    
    def test_decode_query_with_plus(self):
        result = decode_url_parts("http://example.com/search?q=hello+world")
        assert "hello world" in result
    
    def test_decode_encoded_hostname(self):
        result = decode_url_parts("http://example%2Ecom/path")
        assert "example.com" in result
    
    def test_handles_no_encoding(self):
        url = "http://example.com/path"
        result = decode_url_parts(url)
        assert result == url


class TestValidateUrlRegex:
    """Test URL regex validation function"""
    
    def test_valid_http_url(self):
        assert validate_url_regex("http://example.com") == True
    
    def test_valid_https_url(self):
        assert validate_url_regex("https://example.com") == True
    
    def test_valid_url_with_port(self):
        assert validate_url_regex("http://example.com:8080") == True
    
    def test_valid_url_with_path(self):
        assert validate_url_regex("http://example.com/path/to/resource") == True
    
    def test_valid_url_with_query(self):
        assert validate_url_regex("http://example.com/search?q=test") == True
    
    def test_invalid_scheme(self):
        assert validate_url_regex("ftp://example.com") == False
    
    def test_invalid_port_too_high(self):
        assert validate_url_regex("http://example.com:99999") == False
    
    def test_invalid_port_zero(self):
        assert validate_url_regex("http://example.com:0") == False
    
    def test_valid_port_65535(self):
        assert validate_url_regex("http://example.com:65535") == True
    
    def test_valid_port_1(self):
        assert validate_url_regex("http://example.com:1") == True
    
    def test_missing_hostname(self):
        assert validate_url_regex("http://") == False


class TestCheckUrlEndpoint:
    """Test the main URL check endpoint"""
    
    def test_valid_simple_url(self):
        response = client.get("/urlinfo/1/example.com/path")
        assert response.status_code == 200
        data = response.json()
        assert data['valid'] == True
        assert 'url' in data
    
    def test_valid_url_with_port(self):
        response = client.get("/urlinfo/1/example.com:8080/path")
        assert response.status_code == 200
        assert response.json()['valid'] == True
    
    def test_valid_url_with_query(self):
        response = client.get("/urlinfo/1/example.com/search?q=test")
        assert response.status_code == 200
        assert response.json()['valid'] == True
    
    def test_valid_url_with_https_scheme(self):
        response = client.get("/urlinfo/1/https://example.com/path")
        assert response.status_code == 200
        assert response.json()['valid'] == True
    
    def test_invalid_url_missing_hostname(self):
        response = client.get("/urlinfo/1//path")
        assert response.status_code == 400
    
    def test_invalid_port_out_of_range(self):
        response = client.get("/urlinfo/1/example.com:99999/path")
        assert response.status_code == 400
        data = response.json()
        assert 'error' in data['detail']
    
    def test_url_with_encoded_characters(self):
        response = client.get("/urlinfo/1/example.com/path%20with%20spaces")
        assert response.status_code == 200
        data = response.json()
        assert 'path with spaces' in data['url']
    
    def test_hostname_only(self):
        response = client.get("/urlinfo/1/example.com")
        assert response.status_code == 200
        assert response.json()['valid'] == True
    
    def test_subdomain(self):
        response = client.get("/urlinfo/1/subdomain.example.com/path")
        assert response.status_code == 200
        assert response.json()['valid'] == True
    
    def test_complex_path(self):
        response = client.get("/urlinfo/1/example.com/api/v1/users/123")
        assert response.status_code == 200
        assert response.json()['valid'] == True


class TestDatabaseLookup:
    """Test database lookup functionality"""
    
    def test_lookup_known_safe_domain(self):
        response = client.get("/urlinfo/1/example.com/path")
        assert response.status_code == 200
        data = response.json()
        assert data['valid'] == True
        assert data['lookup_result']['found'] == True
        assert data['lookup_result']['status'] == 'safe'
    
    def test_lookup_malicious_domain(self):
        response = client.get("/urlinfo/1/malicious-site.com/download")
        assert response.status_code == 200
        data = response.json()
        assert data['lookup_result']['found'] == True
        assert data['lookup_result']['status'] == 'malicious'
    
    def test_lookup_phishing_domain(self):
        response = client.get("/urlinfo/1/phishing-bank.com")
        assert response.status_code == 200
        data = response.json()
        assert data['lookup_result']['found'] == True
        assert data['lookup_result']['status'] == 'phishing'
    
    def test_lookup_blacklisted_domain(self):
        response = client.get("/urlinfo/1/spam-domain.net")
        assert response.status_code == 200
        data = response.json()
        assert data['lookup_result']['found'] == True
        assert data['lookup_result']['status'] == 'blacklisted'
    
    def test_lookup_unknown_domain(self):
        response = client.get("/urlinfo/1/unknown-domain-xyz.com/path")
        assert response.status_code == 200
        data = response.json()
        assert data['valid'] == True
        assert data['lookup_result']['found'] == False
        assert data['lookup_result']['status'] == 'unknown'


class TestHealthEndpoint:
    """Test health check endpoint"""
    
    def test_health_check(self):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {'status': 'healthy'}
