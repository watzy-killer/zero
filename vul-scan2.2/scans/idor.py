"""
Insecure Direct Object Reference (IDOR) vulnerability scanner module.
"""
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs
from utils import log_message, display_task_start, display_task_complete
from utils.http_client import HTTPClient
import time

def run(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Test for IDOR vulnerabilities.
    
    Args:
        target: Target URL to test
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of vulnerability findings
    """
    findings = test_idor(target, options, ctx)
    return findings


def test_idor(url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test for Insecure Direct Object References with detailed evidence."""
    display_task_start("IDOR Testing")
    findings = []
    
    parsed = urlparse(url)
    if not parsed.query:
        return findings
        
    # Look for numeric IDs in URL parameters
    params = parse_qs(parsed.query)
    client = HTTPClient(timeout=options.get('timeout', 30))
    
    for param_name, param_values in params.items():
        for value in param_values:
            if value.isdigit():
                # Try various object reference manipulations
                test_values = [
                    {"value": str(int(value) + 1), "description": "Incremented object ID"},
                    {"value": str(int(value) - 1), "description": "Decremented object ID"},
                    {"value": "1", "description": "First object ID"},
                    {"value": "0", "description": "Zero object ID"},
                    {"value": "admin", "description": "Admin user reference"},
                    {"value": "true", "description": "Boolean reference"}
                ]
                
                for test_case in test_values:
                    new_value = test_case["value"]
                    new_params = params.copy()
                    new_params[param_name] = [new_value]
                    new_query = "&".join([f"{k}={v}" for k, v in new_params.items()])
                    test_url = url.replace(parsed.query, new_query)
                    
                    try:
                        response = client.get(test_url)
                        original_response = client.get(url)
                        
                        evidence_found = None
                        impact_description = ""
                        access_type = ""
                        
                        # If we get a successful response with different content
                        if response.status_code == 200 and len(response.content) > 0:
                            
                            # Different content than original
                            if response.text != original_response.text:
                                evidence_found = f"IDOR vulnerability with parameter manipulation"
                                impact_description = "Unauthorized access to different object"
                                access_type = "object access"
                            
                            # Different user context detected
                            elif any(user_indicator in response.text for user_indicator in ['admin', 'administrator', 'root', 'superuser']):
                                evidence_found = f"IDOR vulnerability exposing privileged data"
                                impact_description = "Privileged user data accessible"
                                access_type = "privileged access"
                            
                            # Different status code than expected
                            elif original_response.status_code == 403 and response.status_code == 200:
                                evidence_found = f"IDOR vulnerability bypassing authorization"
                                impact_description = "Authorization checks bypassed"
                                access_type = "authorization bypass"
                            
                            if evidence_found:
                                finding = {
                                    "type": "Insecure Direct Object Reference Vulnerability",
                                    "severity": "Medium",
                                    "url": test_url,
                                    "evidence": f"{evidence_found} in parameter '{param_name}'. {test_case['description']}. {impact_description}.",
                                    "description": "The application is vulnerable to Insecure Direct Object Reference attacks, allowing unauthorized access to resources by manipulating object references.",
                                    "remediation": "Implement proper authorization checks for all object accesses. Use indirect object references. Implement access control lists. Validate user permissions for each requested resource.",
                                    "request_data": f"GET {test_url}",
                                    "response_preview": f"Status: {response.status_code} | Access type: {access_type} | Content different: {response.text != original_response.text}",
                                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                                }
                                findings.append(finding)
                                ctx.record_vulnerability(finding)
                                break
                                
                    except Exception as e:
                        log_message(f"Error testing IDOR on {url}: {e}")
    
    display_task_complete("IDOR Testing")
    return findings