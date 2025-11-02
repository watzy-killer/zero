"""
Utility modules for the vulnerability scanner.
"""
from .context import ScanContext
from .http_client import HTTPClient
from .logger import log_message, display_task_start, display_task_complete
from .helpers import extract_links, extract_form_details, is_allowed_by_robots
from .exceptions import ScannerError, RequestFailedError, ScanConfigurationError, CrawlerError

from .logger import display_scan_start, display_scan_complete, display_protection_shield,typing_effect,display_intro


__all__ = [
    'ScanContext',
    'HTTPClient', 
    'log_message',
    'display_intro',
    'display_task_start',
    'display_task_complete',
    'extract_links',
    'extract_form_details',
    'is_allowed_by_robots',
    'ScannerError',
    'RequestFailedError',
    'ScanConfigurationError',
    'CrawlerError',
    'display_scan_start',
    'display_scan_complete',
    'display_protection_shield'
]