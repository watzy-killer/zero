"""
Admin Interfaces discovery module.
"""
from typing import Dict, Any, List
from urllib.parse import urljoin
from utils import log_message, display_task_start, display_task_complete
from utils.http_client import HTTPClient
import time


def run(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Test for common admin interfaces.
    
    Args:
        target: Target URL to test
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of vulnerability findings
    """
    findings = test_for_admin_interfaces(target, options, ctx)
    return findings


def test_for_admin_interfaces(url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test for common admin interfaces."""
    display_task_start("Admin Interfaces Check")
    findings = []
    
    admin_paths = [
        '/admin/', '/administrator/', '/wp-admin/', '/manager/', '/login/',
        '/admin.php', '/admin.asp', '/admin.jsp', '/admin.cgi', '/panel/',
        '/controlpanel/', '/webadmin/', '/cp/', '/backend/', '/console/'
    ]
    
    client = HTTPClient(timeout=options.get('timeout', 30))
    
    for path in admin_paths:
        admin_url = urljoin(url, path)
        
        try:
            response = client.get(admin_url)
            
            if response.status_code == 200:
                # Check for common admin page indicators
                admin_indicators = [
                    'login', 'password', 'username', 'admin', 'administrator',
                    'control panel', 'dashboard', 'wp-admin'
                ]
                
                if any(indicator in response.text.lower() for indicator in admin_indicators):
                    finding = {
                        "type": "Admin Interface Found",
                        "severity": "Info",
                        "url": admin_url,
                        "evidence": f"Admin interface found at {path}",
                        "description": "An admin interface was discovered. This should be protected with strong authentication.",
                        "remediation": "Protect admin interfaces with strong authentication, rate limiting, and IP whitelisting if possible.",
                        "request_data": f"GET {admin_url}",
                        "response_preview": response.text[:500]
                    }
                    findings.append(finding)
                    ctx.record_vulnerability(finding)
                    break
                    
        except Exception as e:
            # Skip errors for admin paths that don't exist
            continue
    
    display_task_complete("Admin Interfaces Check")
    return findings