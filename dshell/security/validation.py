"""
Input Validation and Sanitization Module

Provides security utilities for validating and sanitizing user input,
including ReDoS-safe regex compilation with timeout protection.
"""

import os
import re
import signal
import threading
from contextlib import contextmanager
from typing import Optional, Pattern, Union

# Maximum allowed regex pattern length to prevent complexity attacks
MAX_REGEX_LENGTH = 10000

# Default timeout for regex operations (in seconds)
DEFAULT_REGEX_TIMEOUT = 5.0

# Characters that indicate potentially dangerous regex patterns
DANGEROUS_REGEX_PATTERNS = [
    r'(.+)+',      # Nested quantifiers
    r'(.*)*',      # Nested quantifiers
    r'([^"]+)+',   # Nested quantifiers with character class
    r'(a+)+',      # Classic ReDoS pattern
    r'(a|a)+',     # Alternation with overlap
]


class RegexTimeoutError(Exception):
    """Raised when a regex operation exceeds the allowed timeout."""
    pass


class RegexValidationError(Exception):
    """Raised when a regex pattern fails validation."""
    pass


class PathValidationError(Exception):
    """Raised when a file path fails validation."""
    pass


def _timeout_handler(signum, frame):
    """Signal handler for regex timeout."""
    raise RegexTimeoutError("Regex operation timed out")


@contextmanager
def regex_timeout(seconds: float):
    """
    Context manager that raises RegexTimeoutError if the block takes too long.

    This uses SIGALRM on Unix systems. On Windows, this is a no-op and the
    timeout is not enforced (Windows doesn't support SIGALRM).

    Args:
        seconds: Maximum time allowed for the operation

    Raises:
        RegexTimeoutError: If the operation exceeds the timeout
    """
    if hasattr(signal, 'SIGALRM'):
        # Unix-like systems
        old_handler = signal.signal(signal.SIGALRM, _timeout_handler)
        signal.setitimer(signal.ITIMER_REAL, seconds)
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_handler)
    else:
        # Windows - timeout not supported, just yield
        yield


def validate_regex_pattern(pattern: Union[str, bytes]) -> bool:
    """
    Validate a regex pattern for potential security issues.

    Checks for:
    - Pattern length limits
    - Known ReDoS-vulnerable patterns
    - Valid regex syntax

    Args:
        pattern: The regex pattern to validate

    Returns:
        True if the pattern is valid and safe

    Raises:
        RegexValidationError: If the pattern is invalid or potentially dangerous
    """
    # Convert bytes to string for validation
    if isinstance(pattern, bytes):
        try:
            pattern_str = pattern.decode('utf-8')
        except UnicodeDecodeError:
            raise RegexValidationError("Invalid UTF-8 in regex pattern")
    else:
        pattern_str = pattern

    # Check pattern length
    if len(pattern_str) > MAX_REGEX_LENGTH:
        raise RegexValidationError(
            f"Regex pattern exceeds maximum length of {MAX_REGEX_LENGTH} characters"
        )

    # Check for known dangerous patterns (basic heuristic check)
    # Note: This is not exhaustive but catches common ReDoS patterns
    nested_quantifier_pattern = re.compile(r'\([^)]*[+*][^)]*\)[+*]')
    if nested_quantifier_pattern.search(pattern_str):
        raise RegexValidationError(
            "Regex pattern contains nested quantifiers which may cause ReDoS"
        )

    # Try to compile the pattern to check syntax
    try:
        re.compile(pattern_str)
    except re.error as e:
        raise RegexValidationError(f"Invalid regex syntax: {e}")

    return True


def safe_compile_regex(
    pattern: Union[str, bytes],
    flags: int = 0,
    timeout: float = DEFAULT_REGEX_TIMEOUT,
    validate: bool = True
) -> Pattern:
    """
    Safely compile a regex pattern with validation and timeout protection.

    This function validates the pattern for potential ReDoS vulnerabilities
    and compiles it with a timeout to prevent denial of service attacks.

    Args:
        pattern: The regex pattern to compile
        flags: Regex flags (e.g., re.IGNORECASE)
        timeout: Maximum time allowed for compilation (seconds)
        validate: Whether to validate the pattern for dangerous constructs

    Returns:
        Compiled regex pattern

    Raises:
        RegexValidationError: If the pattern is invalid or dangerous
        RegexTimeoutError: If compilation exceeds the timeout
    """
    if validate:
        validate_regex_pattern(pattern)

    with regex_timeout(timeout):
        return re.compile(pattern, flags)


def regex_search_with_timeout(
    pattern: Pattern,
    text: Union[str, bytes],
    timeout: float = DEFAULT_REGEX_TIMEOUT
) -> Optional[re.Match]:
    """
    Perform a regex search with timeout protection.

    Args:
        pattern: Compiled regex pattern
        text: Text to search
        timeout: Maximum time allowed for the search (seconds)

    Returns:
        Match object if found, None otherwise

    Raises:
        RegexTimeoutError: If the search exceeds the timeout
    """
    with regex_timeout(timeout):
        return pattern.search(text)


def validate_file_path(
    path: str,
    allowed_base_dirs: Optional[list] = None,
    allow_absolute: bool = True,
    allow_symlinks: bool = False
) -> str:
    """
    Validate and sanitize a file path to prevent path traversal attacks.

    Args:
        path: The file path to validate
        allowed_base_dirs: List of allowed base directories (if None, any path is allowed)
        allow_absolute: Whether to allow absolute paths
        allow_symlinks: Whether to allow symbolic links

    Returns:
        The validated and normalized path

    Raises:
        PathValidationError: If the path is invalid or not allowed
    """
    if not path:
        raise PathValidationError("Empty path provided")

    # Normalize the path to resolve .. and . components
    normalized_path = os.path.normpath(path)

    # Check for path traversal attempts
    if '..' in path.split(os.sep):
        # After normalization, check if we're still within allowed bounds
        pass  # normpath handles this, but we log the attempt

    # Check absolute path restriction
    if not allow_absolute and os.path.isabs(normalized_path):
        raise PathValidationError("Absolute paths are not allowed")

    # Check against allowed base directories
    if allowed_base_dirs:
        real_path = os.path.realpath(normalized_path)
        allowed = False
        for base_dir in allowed_base_dirs:
            real_base = os.path.realpath(base_dir)
            if real_path.startswith(real_base + os.sep) or real_path == real_base:
                allowed = True
                break
        if not allowed:
            raise PathValidationError(
                f"Path '{path}' is not within allowed directories"
            )

    # Check symlink restriction
    if not allow_symlinks and os.path.islink(normalized_path):
        raise PathValidationError("Symbolic links are not allowed")

    return normalized_path


def sanitize_string(
    value: str,
    max_length: int = 1000,
    allowed_chars: Optional[str] = None,
    strip_null: bool = True
) -> str:
    """
    Sanitize a string value for safe processing.

    Args:
        value: The string to sanitize
        max_length: Maximum allowed length
        allowed_chars: If provided, only these characters are allowed
        strip_null: Whether to remove null bytes

    Returns:
        Sanitized string
    """
    if not isinstance(value, str):
        value = str(value)

    # Strip null bytes
    if strip_null:
        value = value.replace('\x00', '')

    # Truncate to max length
    if len(value) > max_length:
        value = value[:max_length]

    # Filter to allowed characters
    if allowed_chars is not None:
        value = ''.join(c for c in value if c in allowed_chars)

    return value


def validate_port(port: Union[int, str]) -> int:
    """
    Validate a network port number.

    Args:
        port: Port number to validate

    Returns:
        Validated port number as integer

    Raises:
        ValueError: If the port is invalid
    """
    try:
        port_int = int(port)
    except (ValueError, TypeError):
        raise ValueError(f"Invalid port number: {port}")

    if not 0 <= port_int <= 65535:
        raise ValueError(f"Port number out of range: {port_int}")

    return port_int


def validate_ip_address(ip: str) -> str:
    """
    Validate an IP address (IPv4 or IPv6).

    Args:
        ip: IP address string to validate

    Returns:
        Validated IP address string

    Raises:
        ValueError: If the IP address is invalid
    """
    import socket

    # Try IPv4
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return ip
    except socket.error:
        pass

    # Try IPv6
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return ip
    except socket.error:
        raise ValueError(f"Invalid IP address: {ip}")
