"""
HTTP client utilities for making web requests.
"""
import requests
from typing import Dict, Any, Optional
from urllib.parse import urljoin, urlparse
from .exceptions import RequestFailedError


class HTTPClient:
    """Wrapper for HTTP requests with common security scanner functionality."""
    
    def __init__(self, base_headers: Optional[Dict[str, str]] = None, timeout: int = 30):
        self.session = requests.Session()
        self.timeout = timeout
        self.session.headers.update(base_headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """Make GET request with error handling."""
        try:
            return self.session.get(url, timeout=self.timeout, **kwargs)
        except requests.RequestException as e:
            raise RequestFailedError(f"GET request failed for {url}: {e}")
    
    def post(self, url: str, data: Optional[Dict] = None, **kwargs) -> requests.Response:
        """Make POST request with error handling."""
        try:
            return self.session.post(url, data=data, timeout=self.timeout, **kwargs)
        except requests.RequestException as e:
            raise RequestFailedError(f"POST request failed for {url}: {e}")
    
    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make custom HTTP request."""
        try:
            return self.session.request(method, url, timeout=self.timeout, **kwargs)
        except requests.RequestException as e:
            raise RequestFailedError(f"{method} request failed for {url}: {e}")