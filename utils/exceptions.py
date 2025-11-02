"""
Custom exceptions for the vulnerability scanner.
"""

class ScannerError(Exception):
    """Base exception for scanner-related errors."""
    pass

class RequestFailedError(ScannerError):
    """Raised when an HTTP request fails."""
    pass

class ScanConfigurationError(ScannerError):
    """Raised when there's an issue with scan configuration."""
    pass

class CrawlerError(ScannerError):
    """Raised when web crawling encounters an error."""
    pass