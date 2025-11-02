"""
Open Redirect vulnerability scanner module.
"""
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs
from utils import log_message, display_task_start, display_task_complete
from utils.http_client import HTTPClient
import time

def run(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Test for open redirect vulnerabilities.
    
    Args:
        target: Target URL to test
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of vulnerability findings
    """
    findings = test_open_redirect(target, options, ctx)
    return findings


def test_open_redirect(url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test for open redirect vulnerabilities with detailed evidence."""
    display_task_start("Open Redirect Testing")
    findings = []
    
    parsed = urlparse(url)
    if not parsed.query:
        return findings
        
    test_redirects = [
        {"payload": "https://evil.com", "description": "External domain redirect"},
        {"payload": "//evil.com", "description": "Protocol-relative redirect"},
        {"payload": "http://evil.com", "description": "HTTP external redirect"},
        {"payload": "https://attacker.com/phishing", "description": "Phishing URL redirect"}
    ]
    
    params = parse_qs(parsed.query)
    client = HTTPClient(timeout=options.get('timeout', 30))
    
    for param_name in params.keys():
        if any(redirect in param_name.lower() for redirect in ['url', 'redirect', 'next', 'return', 'goto']):
            for test_case in test_redirects:
                payload = test_case["payload"]
                test_params = params.copy()
                test_params[param_name] = payload
                new_query = "&".join([f"{k}={v}" for k, v in test_params.items()])
                test_url = url.replace(parsed.query, new_query)
                
                try:
                    response = client.get(test_url, allow_redirects=False)
                    
                    evidence_found = None
                    impact_description = ""
                    redirect_type = ""
                    
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('location', '')
                        
                        # External domain redirect
                        if payload in location:
                            evidence_found = f"Open redirect to external domain"
                            impact_description = "Users can be redirected to malicious sites"
                            redirect_type = "external domain"
                        
                        # Protocol-relative redirect
                        elif location.startswith('//') and 'evil.com' in location:
                            evidence_found = f"Protocol-relative open redirect"
                            impact_description = "Redirect inherits protocol of current site"
                            redirect_type = "protocol-relative"
                        
                        # Domain whitelist bypass
                        elif any(bypass in location for bypass in ['.evil.com', 'evil.com?', '@evil.com']):
                            evidence_found = f"Open redirect with whitelist bypass"
                            impact_description = "Domain validation can be circumvented"
                            redirect_type = "whitelist bypass"
                        
                        if evidence_found:
                            finding = {
                                "type": "Open Redirect Vulnerability",
                                "severity": "Medium",
                                "url": test_url,
                                "evidence": f"{evidence_found} via parameter '{param_name}'. {test_case['description']}. {impact_description}.",
                                "description": "The application is vulnerable to open redirect attacks, allowing attackers to redirect users to malicious websites while maintaining the appearance of legitimacy.",
                                "remediation": "Validate redirect URLs against a strict allow list of permitted domains. Implement server-side redirect validation. Use relative URLs for internal redirects. Avoid passing full URLs in parameters.",
                                "request_data": f"GET {test_url}",
                                "response_preview": f"Status: {response.status_code} | Location: {location} | Redirect type: {redirect_type}",
                                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                            }
                            findings.append(finding)
                            ctx.record_vulnerability(finding)
                            break
                            
                except Exception as e:
                    log_message(f"Error testing open redirect on {url}: {e}")
    
    display_task_complete("Open Redirect Testing")
    return findings