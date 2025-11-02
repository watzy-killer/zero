"""
Security Headers scanner module.
"""
from typing import Dict, Any, List
from utils import log_message, display_task_start, display_task_complete
from utils.http_client import HTTPClient


def run(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Test for missing security headers.
    
    Args:
        target: Target URL to test
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of vulnerability findings
    """
    findings = test_http_security_headers(target, options, ctx)
    return findings


def test_http_security_headers(url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test for missing security headers."""
    display_task_start("Security Headers Check")
    findings = []
    
    security_headers = [
        'Content-Security-Policy',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Strict-Transport-Security',
        'Referrer-Policy',
        'X-Permitted-Cross-Domain-Policies',
        'X-XSS-Protection'
    ]
    
    client = HTTPClient(timeout=options.get('timeout', 30))
    
    try:
        response = client.get(url)
        headers = response.headers
        
        missing_headers = []
        for header in security_headers:
            if header not in headers:
                missing_headers.append(header)
        
        if missing_headers:
            finding = {
                "type": "Missing Security Headers",
                "severity": "Low",
                "url": url,
                "evidence": f"Missing headers: {', '.join(missing_headers)}",
                "description": "The application is missing important security headers.",
                "remediation": "Implement appropriate security headers based on OWASP guidelines.",
                "request_data": f"GET {url}",
                "response_preview": f"Headers: {dict(headers)}"
            }
            findings.append(finding)
            ctx.record_vulnerability(finding)
            
    except Exception as e:
        log_message(f"Error checking security headers: {e}")
    
    display_task_complete("Security Headers Check")
    return findings