"""
Structured Security Logging Module

Provides security-focused logging utilities for the Dshell network forensic
analysis framework, including:
- Structured JSON logging for SIEM integration
- Security event logging with severity levels
- Audit logging for sensitive operations
- Rate limiting utilities for network operations
"""

import json
import logging
import os
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union
from functools import wraps

# Security event severity levels
SEVERITY_INFO = "INFO"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"

# Security event categories
CATEGORY_AUTHENTICATION = "authentication"
CATEGORY_AUTHORIZATION = "authorization"
CATEGORY_DATA_ACCESS = "data_access"
CATEGORY_NETWORK = "network"
CATEGORY_PLUGIN = "plugin"
CATEGORY_CONFIGURATION = "configuration"
CATEGORY_SECURITY_SCAN = "security_scan"


class StructuredFormatter(logging.Formatter):
    """
    Custom log formatter that outputs structured JSON logs.

    This formatter is designed for integration with SIEM systems and
    log aggregation platforms like Elasticsearch, Splunk, etc.
    """

    def __init__(self, include_extra: bool = True):
        super().__init__()
        self.include_extra = include_extra

    def format(self, record: logging.LogRecord) -> str:
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        # Add extra fields if present
        if self.include_extra:
            extra_fields = {
                k: v for k, v in record.__dict__.items()
                if k not in logging.LogRecord(
                    "", 0, "", 0, "", (), None
                ).__dict__ and not k.startswith('_')
            }
            if extra_fields:
                log_entry["extra"] = extra_fields

        return json.dumps(log_entry, default=str)


class SecurityLogger:
    """
    Security-focused logger for Dshell operations.

    Provides methods for logging security events with proper categorization,
    severity levels, and structured data for SIEM integration.
    """

    def __init__(
        self,
        name: str = "dshell.security",
        level: int = logging.INFO,
        json_output: bool = False,
        log_file: Optional[str] = None
    ):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)

        # Remove existing handlers
        self.logger.handlers = []

        # Create handler
        if log_file:
            handler = logging.FileHandler(log_file)
        else:
            handler = logging.StreamHandler(sys.stderr)

        # Set formatter
        if json_output:
            handler.setFormatter(StructuredFormatter())
        else:
            handler.setFormatter(logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            ))

        self.logger.addHandler(handler)

    def log_security_event(
        self,
        message: str,
        severity: str = SEVERITY_INFO,
        category: str = CATEGORY_SECURITY_SCAN,
        source_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
        user: Optional[str] = None,
        plugin: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Log a security event with structured metadata.

        Args:
            message: Human-readable event description
            severity: Event severity level
            category: Event category for classification
            source_ip: Source IP address (if applicable)
            dest_ip: Destination IP address (if applicable)
            user: User associated with the event
            plugin: Plugin that generated the event
            details: Additional event details
        """
        extra = {
            "event_type": "security",
            "severity": severity,
            "category": category,
        }

        if source_ip:
            extra["source_ip"] = source_ip
        if dest_ip:
            extra["dest_ip"] = dest_ip
        if user:
            extra["user"] = user
        if plugin:
            extra["plugin"] = plugin
        if details:
            extra["details"] = details

        # Map severity to log level
        level_map = {
            SEVERITY_INFO: logging.INFO,
            SEVERITY_LOW: logging.INFO,
            SEVERITY_MEDIUM: logging.WARNING,
            SEVERITY_HIGH: logging.ERROR,
            SEVERITY_CRITICAL: logging.CRITICAL,
        }

        self.logger.log(level_map.get(severity, logging.INFO), message, extra=extra)

    def log_audit_event(
        self,
        action: str,
        resource: str,
        user: Optional[str] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Log an audit event for sensitive operations.

        Args:
            action: The action performed (e.g., "read", "write", "delete")
            resource: The resource affected
            user: User who performed the action
            success: Whether the action succeeded
            details: Additional audit details
        """
        extra = {
            "event_type": "audit",
            "action": action,
            "resource": resource,
            "success": success,
        }

        if user:
            extra["user"] = user
        if details:
            extra["details"] = details

        level = logging.INFO if success else logging.WARNING
        message = f"Audit: {action} on {resource} - {'success' if success else 'failed'}"
        self.logger.log(level, message, extra=extra)

    def log_plugin_activity(
        self,
        plugin_name: str,
        action: str,
        connection_info: Optional[Dict[str, Any]] = None,
        findings: Optional[list] = None
    ):
        """
        Log plugin activity for monitoring unusual patterns.

        Args:
            plugin_name: Name of the plugin
            action: Action performed by the plugin
            connection_info: Connection metadata
            findings: Any security findings from the plugin
        """
        extra = {
            "event_type": "plugin_activity",
            "plugin": plugin_name,
            "action": action,
        }

        if connection_info:
            extra["connection"] = connection_info
        if findings:
            extra["findings"] = findings

        self.logger.info(f"Plugin {plugin_name}: {action}", extra=extra)


class RateLimiter:
    """
    Thread-safe rate limiter for network capture operations.

    Implements a token bucket algorithm to limit the rate of operations.
    """

    def __init__(
        self,
        max_rate: float,
        time_window: float = 1.0,
        burst_size: Optional[int] = None
    ):
        """
        Initialize the rate limiter.

        Args:
            max_rate: Maximum operations per time window
            time_window: Time window in seconds
            burst_size: Maximum burst size (defaults to max_rate)
        """
        self.max_rate = max_rate
        self.time_window = time_window
        self.burst_size = burst_size or int(max_rate)
        self.tokens = self.burst_size
        self.last_update = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens: int = 1, blocking: bool = True) -> bool:
        """
        Acquire tokens from the rate limiter.

        Args:
            tokens: Number of tokens to acquire
            blocking: Whether to block until tokens are available

        Returns:
            True if tokens were acquired, False otherwise
        """
        with self._lock:
            self._refill()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True

            if not blocking:
                return False

        # Blocking mode: wait for tokens
        while True:
            time.sleep(0.01)  # Small sleep to avoid busy waiting
            with self._lock:
                self._refill()
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True

    def _refill(self):
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.last_update
        self.last_update = now

        # Add tokens based on elapsed time
        new_tokens = elapsed * (self.max_rate / self.time_window)
        self.tokens = min(self.burst_size, self.tokens + new_tokens)


def rate_limited(limiter: RateLimiter):
    """
    Decorator to apply rate limiting to a function.

    Args:
        limiter: RateLimiter instance to use

    Returns:
        Decorated function
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            limiter.acquire()
            return func(*args, **kwargs)
        return wrapper
    return decorator


# Global security logger instance
_security_logger: Optional[SecurityLogger] = None


def get_security_logger() -> SecurityLogger:
    """
    Get the global security logger instance.

    Creates a new instance if one doesn't exist, using environment
    variables for configuration.

    Returns:
        SecurityLogger instance
    """
    global _security_logger

    if _security_logger is None:
        log_level = os.environ.get("DSHELL_LOG_LEVEL", "INFO")
        json_logging = os.environ.get("DSHELL_JSON_LOGGING", "false").lower() == "true"
        log_file = os.environ.get("DSHELL_LOG_FILE")

        level_map = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL,
        }

        _security_logger = SecurityLogger(
            level=level_map.get(log_level.upper(), logging.INFO),
            json_output=json_logging,
            log_file=log_file
        )

    return _security_logger


def log_security_event(
    message: str,
    severity: str = SEVERITY_INFO,
    category: str = CATEGORY_SECURITY_SCAN,
    **kwargs
):
    """
    Convenience function to log a security event using the global logger.

    Args:
        message: Event message
        severity: Event severity
        category: Event category
        **kwargs: Additional event metadata
    """
    get_security_logger().log_security_event(
        message, severity=severity, category=category, **kwargs
    )
