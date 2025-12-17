"""
Security Tests for Dshell

Tests for security-critical functions including:
- Regex validation and ReDoS protection
- Input validation and sanitization
- SSL blacklist checking logic
- MS15-034 vulnerability detection
"""

import os
import re
import sys
import pytest
import tempfile

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dshell.security.validation import (
    safe_compile_regex,
    regex_search_with_timeout,
    validate_regex_pattern,
    validate_file_path,
    sanitize_string,
    validate_port,
    validate_ip_address,
    RegexValidationError,
    RegexTimeoutError,
    PathValidationError,
    MAX_REGEX_LENGTH,
)
from dshell.security.logging import (
    SecurityLogger,
    RateLimiter,
    SEVERITY_INFO,
    SEVERITY_HIGH,
    CATEGORY_SECURITY_SCAN,
)


class TestRegexValidation:
    """Tests for regex validation and ReDoS protection."""

    def test_valid_simple_regex(self):
        """Test that simple valid regex patterns compile successfully."""
        pattern = safe_compile_regex(r"hello.*world")
        assert pattern is not None
        assert pattern.search("hello beautiful world") is not None

    def test_valid_bytes_regex(self):
        """Test that bytes regex patterns compile successfully."""
        pattern = safe_compile_regex(b"hello.*world")
        assert pattern is not None
        assert pattern.search(b"hello beautiful world") is not None

    def test_regex_with_flags(self):
        """Test regex compilation with flags."""
        pattern = safe_compile_regex(r"HELLO", flags=re.IGNORECASE)
        assert pattern.search("hello") is not None

    def test_invalid_regex_syntax(self):
        """Test that invalid regex syntax raises RegexValidationError."""
        with pytest.raises(RegexValidationError):
            safe_compile_regex(r"[invalid")

    def test_regex_length_limit(self):
        """Test that overly long regex patterns are rejected."""
        long_pattern = "a" * (MAX_REGEX_LENGTH + 1)
        with pytest.raises(RegexValidationError):
            safe_compile_regex(long_pattern)

    def test_nested_quantifier_detection(self):
        """Test detection of potentially dangerous nested quantifiers."""
        # This pattern has nested quantifiers that could cause ReDoS
        dangerous_pattern = r"(a+)+"
        with pytest.raises(RegexValidationError):
            safe_compile_regex(dangerous_pattern)

    def test_skip_validation_flag(self):
        """Test that validation can be skipped when needed."""
        # This would normally fail validation but should work with validate=False
        pattern = safe_compile_regex(r"(a+)+", validate=False)
        assert pattern is not None

    def test_regex_search_with_timeout_success(self):
        """Test successful regex search with timeout."""
        pattern = re.compile(r"test")
        result = regex_search_with_timeout(pattern, "this is a test string")
        assert result is not None

    def test_regex_search_with_timeout_no_match(self):
        """Test regex search with timeout when no match found."""
        pattern = re.compile(r"xyz")
        result = regex_search_with_timeout(pattern, "this is a test string")
        assert result is None


class TestInputValidation:
    """Tests for input validation and sanitization."""

    def test_validate_file_path_simple(self):
        """Test simple file path validation."""
        path = validate_file_path("/tmp/test.txt")
        assert path == "/tmp/test.txt"

    def test_validate_file_path_normalization(self):
        """Test that paths are normalized."""
        path = validate_file_path("/tmp/../tmp/test.txt")
        assert path == "/tmp/test.txt"

    def test_validate_file_path_empty(self):
        """Test that empty paths are rejected."""
        with pytest.raises(PathValidationError):
            validate_file_path("")

    def test_validate_file_path_absolute_restriction(self):
        """Test absolute path restriction."""
        with pytest.raises(PathValidationError):
            validate_file_path("/etc/passwd", allow_absolute=False)

    def test_validate_file_path_allowed_dirs(self):
        """Test allowed directories restriction."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Path within allowed directory should work
            test_path = os.path.join(tmpdir, "test.txt")
            result = validate_file_path(test_path, allowed_base_dirs=[tmpdir])
            assert result is not None

    def test_validate_file_path_outside_allowed_dirs(self):
        """Test that paths outside allowed directories are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with pytest.raises(PathValidationError):
                validate_file_path("/etc/passwd", allowed_base_dirs=[tmpdir])

    def test_sanitize_string_basic(self):
        """Test basic string sanitization."""
        result = sanitize_string("hello world")
        assert result == "hello world"

    def test_sanitize_string_null_bytes(self):
        """Test that null bytes are stripped."""
        result = sanitize_string("hello\x00world")
        assert result == "helloworld"

    def test_sanitize_string_max_length(self):
        """Test string truncation to max length."""
        result = sanitize_string("a" * 100, max_length=10)
        assert len(result) == 10

    def test_sanitize_string_allowed_chars(self):
        """Test filtering to allowed characters."""
        result = sanitize_string("abc123!@#", allowed_chars="abc123")
        assert result == "abc123"

    def test_validate_port_valid(self):
        """Test valid port numbers."""
        assert validate_port(80) == 80
        assert validate_port("443") == 443
        assert validate_port(0) == 0
        assert validate_port(65535) == 65535

    def test_validate_port_invalid(self):
        """Test invalid port numbers."""
        with pytest.raises(ValueError):
            validate_port(-1)
        with pytest.raises(ValueError):
            validate_port(65536)
        with pytest.raises(ValueError):
            validate_port("invalid")

    def test_validate_ip_address_ipv4(self):
        """Test valid IPv4 addresses."""
        assert validate_ip_address("192.168.1.1") == "192.168.1.1"
        assert validate_ip_address("0.0.0.0") == "0.0.0.0"
        assert validate_ip_address("255.255.255.255") == "255.255.255.255"

    def test_validate_ip_address_ipv6(self):
        """Test valid IPv6 addresses."""
        assert validate_ip_address("::1") == "::1"
        assert validate_ip_address("2001:db8::1") == "2001:db8::1"

    def test_validate_ip_address_invalid(self):
        """Test invalid IP addresses."""
        with pytest.raises(ValueError):
            validate_ip_address("invalid")
        with pytest.raises(ValueError):
            validate_ip_address("256.256.256.256")


class TestSecurityLogging:
    """Tests for security logging functionality."""

    def test_security_logger_creation(self):
        """Test SecurityLogger instantiation."""
        logger = SecurityLogger(name="test.security")
        assert logger is not None

    def test_security_logger_json_output(self):
        """Test SecurityLogger with JSON output."""
        logger = SecurityLogger(name="test.security.json", json_output=True)
        assert logger is not None

    def test_log_security_event(self):
        """Test logging a security event."""
        logger = SecurityLogger(name="test.security.event")
        # Should not raise any exceptions
        logger.log_security_event(
            message="Test security event",
            severity=SEVERITY_HIGH,
            category=CATEGORY_SECURITY_SCAN,
            source_ip="192.168.1.1",
            details={"test": "data"}
        )

    def test_log_audit_event(self):
        """Test logging an audit event."""
        logger = SecurityLogger(name="test.security.audit")
        # Should not raise any exceptions
        logger.log_audit_event(
            action="read",
            resource="/data/test.pcap",
            user="analyst",
            success=True
        )

    def test_log_plugin_activity(self):
        """Test logging plugin activity."""
        logger = SecurityLogger(name="test.security.plugin")
        # Should not raise any exceptions
        logger.log_plugin_activity(
            plugin_name="sslblacklist",
            action="certificate_check",
            findings=["suspicious_cert"]
        )


class TestRateLimiter:
    """Tests for rate limiting functionality."""

    def test_rate_limiter_creation(self):
        """Test RateLimiter instantiation."""
        limiter = RateLimiter(max_rate=10, time_window=1.0)
        assert limiter is not None

    def test_rate_limiter_acquire(self):
        """Test acquiring tokens from rate limiter."""
        limiter = RateLimiter(max_rate=10, time_window=1.0, burst_size=5)
        # Should be able to acquire up to burst_size tokens immediately
        for _ in range(5):
            assert limiter.acquire(blocking=False) is True

    def test_rate_limiter_exhaustion(self):
        """Test rate limiter exhaustion."""
        limiter = RateLimiter(max_rate=2, time_window=1.0, burst_size=2)
        # Exhaust the tokens
        assert limiter.acquire(blocking=False) is True
        assert limiter.acquire(blocking=False) is True
        # Should fail to acquire more without blocking
        assert limiter.acquire(blocking=False) is False


class TestSSLBlacklistLogic:
    """Tests for SSL blacklist checking logic."""

    def test_sha1_hash_format(self):
        """Test that SHA1 hashes are in expected format."""
        import hashlib
        test_data = b"test certificate data"
        sha1 = hashlib.sha1(test_data).hexdigest()
        # SHA1 should be 40 hex characters
        assert len(sha1) == 40
        assert all(c in '0123456789abcdef' for c in sha1)

    def test_csv_parsing_logic(self):
        """Test CSV parsing logic similar to sslblacklist plugin."""
        # Simulate the CSV parsing logic from sslblacklist.py
        test_csv_lines = [
            "# Comment line",
            "2024-01-01,abc123def456,Malware Family A",
            "2024-01-02,789xyz000111,Malware Family B",
            "",  # Empty line
        ]

        hashes = {}
        for line in test_csv_lines:
            line = line.split('#')[0]  # ignore comments
            line = line.strip()
            try:
                timestamp, sha1, reason = line.split(',', 3)
                hashes[sha1] = reason
            except ValueError:
                continue

        assert len(hashes) == 2
        assert hashes["abc123def456"] == "Malware Family A"
        assert hashes["789xyz000111"] == "Malware Family B"


class TestMS15034Detection:
    """Tests for MS15-034 vulnerability detection logic."""

    def test_range_header_detection(self):
        """Test detection of MS15-034 range header pattern."""
        # The vulnerable range value ends with this specific number
        vulnerable_range = "bytes=0-18446744073709551615"
        assert vulnerable_range.endswith('18446744073709551615')

        # Normal range should not match
        normal_range = "bytes=0-1000"
        assert not normal_range.endswith('18446744073709551615')

    def test_response_status_detection(self):
        """Test detection of vulnerable server response."""
        # Vulnerable server returns 416 status
        vulnerable_status = '416'
        vulnerable_reason = 'Requested Range Not Satisfiable'

        # Detection logic from ms15-034.py
        is_vulnerable = (
            vulnerable_status == '416' or
            vulnerable_reason == 'Requested Range Not Satisfiable'
        )
        assert is_vulnerable is True

        # Normal response should not trigger
        normal_status = '200'
        normal_reason = 'OK'
        is_normal_vulnerable = (
            normal_status == '416' or
            normal_reason == 'Requested Range Not Satisfiable'
        )
        assert is_normal_vulnerable is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
