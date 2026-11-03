"""Unit tests for decrypto_assumption_scan module."""

import sys
from pathlib import Path

# Add parent directory to path so we can import the modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from decrypto_assumption_scan import normalize_url, validate_url, new_finding, cookie_metadata
from email.message import Message


def test_normalize_url_https():
    """Test URL normalization for HTTPS."""
    url = "https://example.com/path"
    result = normalize_url(url)
    assert result == "https://example.com/path"


def test_normalize_url_removes_port_443():
    """Test that port 443 is removed from HTTPS URLs."""
    url = "https://example.com:443/path"
    result = normalize_url(url)
    assert result == "https://example.com/path"


def test_normalize_url_removes_port_80():
    """Test that port 80 is removed from HTTP localhost URLs."""
    url = "http://localhost:80/path"
    result = normalize_url(url)
    assert result == "http://localhost/path"


def test_normalize_url_rejects_query_string():
    """Test that URLs with query strings are rejected."""
    try:
        normalize_url("https://example.com/path?query=value")
        raise AssertionError("Should have raised ValueError")
    except ValueError:
        pass


def test_normalize_url_rejects_credentials():
    """Test that URLs with embedded credentials are rejected."""
    try:
        normalize_url("https://user:pass@example.com/path")
        raise AssertionError("Should have raised ValueError")
    except ValueError:
        pass


def test_normalize_url_rejects_http_non_localhost():
    """Test that non-HTTPS URLs are rejected unless localhost."""
    try:
        normalize_url("http://example.com/path")
        raise AssertionError("Should have raised ValueError")
    except ValueError:
        pass


def test_normalize_url_allows_http_localhost():
    """Test that HTTP is allowed on localhost."""
    url = "http://localhost/path"
    result = normalize_url(url)
    assert result == "http://localhost/path"


def test_validate_url_delegates_to_normalize():
    """Test that validate_url delegates to normalize_url."""
    url = "https://example.com/path"
    result = validate_url(url)
    assert result == normalize_url(url)


def test_new_finding_creates_valid_structure():
    """Test that new_finding creates correctly structured findings."""
    finding = new_finding(
        rule="TEST-RULE",
        url="https://example.com",
        title="Test Finding",
        assumption="Test assumption",
        evidence={"key": "value"},
        reasoning="Test reasoning",
        fix="Test fix",
        verification="Test verification"
    )
    assert "id" in finding
    assert finding["rule"] == "TEST-RULE"
    assert finding["target"] == "https://example.com"
    assert finding["title"] == "Test Finding"
    assert len(finding["id"]) == 10


def test_cookie_metadata_empty_headers():
    """Test cookie metadata extraction from empty headers."""
    headers = Message()
    result = cookie_metadata(headers)
    assert result == []


def test_cookie_metadata_session_like_detection():
    """Test detection of session-like cookie names."""
    headers = Message()
    headers["Set-Cookie"] = "sessionid=abc123; Secure; HttpOnly"
    result = cookie_metadata(headers)
    assert len(result) == 1
    assert result[0]["session_like"] is True
    assert result[0]["secure"] is True
    assert result[0]["httponly"] is True


def load_tests(loader, tests, pattern):
    """Include standalone function controls in the stdlib CI test suite."""
    import unittest
    tests.addTests(unittest.FunctionTestCase(value) for name, value in globals().items()
                   if name.startswith("test_") and callable(value))
    return tests
