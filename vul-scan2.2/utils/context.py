"""
Context dataclass for sharing state between scan modules.
"""
from dataclasses import dataclass, field
from typing import Set, List, Dict, Any, Optional
from urllib.parse import urlparse
import requests
from collections import deque


@dataclass
class ScanContext:
    """Shared context for vulnerability scanning operations."""
    
    target_url: str
    session: requests.Session
    visited_urls: Set[str] = field(default_factory=set)
    to_visit: deque = field(default_factory=deque)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    failed_requests: List[Dict[str, Any]] = field(default_factory=list)
    robots_txt: Optional[str] = None
    scan_start_time: Optional[float] = None
    scan_end_time: Optional[float] = None
    auth_cookies: Dict[str, str] = field(default_factory=dict)
    
    def is_same_domain(self, url: str) -> bool:
        """Check if URL belongs to the same domain as target."""
        return urlparse(url).netloc == urlparse(self.target_url).netloc
    
    def record_vulnerability(self, vuln_data: Dict[str, Any]) -> None:
        """Record a vulnerability finding."""
        # Check for duplicates
        for vuln in self.vulnerabilities:
            if (vuln['type'] == vuln_data['type'] and 
                vuln['url'] == vuln_data['url'] and 
                vuln['evidence'] == vuln_data['evidence']):
                return
        self.vulnerabilities.append(vuln_data)