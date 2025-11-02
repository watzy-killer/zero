"""
HTTP Methods vulnerability scanner module.
"""
from typing import Dict, Any, List
from utils import log_message, display_task_start, display_task_complete
from utils.http_client import HTTPClient
import time

def run(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Test for potentially dangerous HTTP methods.
    
    Args:
        target: Target URL to test
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of vulnerability findings
    """
    findings = test_http_methods(target, options, ctx)
    return findings


def test_http_methods(url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test for potentially dangerous HTTP methods with detailed evidence."""
    display_task_start("HTTP Methods Testing")
    findings = []
    
    dangerous_methods = [
        {"method": "PUT", "risk": "File upload/modification", "severity": "Medium"},
        {"method": "DELETE", "risk": "File/resource deletion", "severity": "High"},
        {"method": "TRACE", "risk": "Cross-site tracing attacks", "severity": "Low"},
        {"method": "CONNECT", "risk": "Proxy tunneling", "severity": "Medium"},
        {"method": "PATCH", "risk": "Partial resource modification", "severity": "Medium"},
        {"method": "OPTIONS", "risk": "Information disclosure", "severity": "Low"}
    ]
    
    client = HTTPClient(timeout=options.get('timeout', 30))
    
    for test_case in dangerous_methods:
        method = test_case["method"]
        risk_description = test_case["risk"]
        base_severity = test_case["severity"]
        
        try:
            response = client.request(method, url)
            
            evidence_found = None
            impact_description = ""
            method_behavior = ""
            
            # Method enabled and functional
            if response.status_code not in [405, 501]:  # If not "Method Not Allowed"
                
                # Successful operation (2xx status)
                if 200 <= response.status_code < 300:
                    evidence_found = f"HTTP {method} method enabled and operational"
                    impact_description = f"{risk_description} possible"
                    method_behavior = "operational"
                    severity = "High" if method in ["DELETE"] else base_severity
                
                # Client error but method accepted (4xx status)
                elif 400 <= response.status_code < 500:
                    evidence_found = f"HTTP {method} method enabled with client errors"
                    impact_description = f"{risk_description} potentially possible"
                    method_behavior = "accepted with errors"
                    severity = base_severity
                
                # Server error but method accepted (5xx status)  
                elif 500 <= response.status_code < 600:
                    evidence_found = f"HTTP {method} method enabled with server errors"
                    impact_description = f"{risk_description} potentially possible"
                    method_behavior = "accepted with server errors"
                    severity = base_severity
                
                if evidence_found:
                    finding = {
                        "type": "Dangerous HTTP Method Enabled",
                        "severity": severity,
                        "url": url,
                        "evidence": f"{evidence_found}. {impact_description}. HTTP {method} requests are accepted by the server.",
                        "description": f"The {method} HTTP method is enabled, which could be abused for {risk_description.lower()} if proper access controls are not implemented.",
                        "remediation": "Disable unnecessary HTTP methods in web server configuration. Implement proper authentication and authorization for all methods. Use web application firewalls to filter dangerous methods.",
                        "request_data": f"{method} {url}",
                        "response_preview": f"Status: {response.status_code} | Method behavior: {method_behavior}",
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    findings.append(finding)
                    ctx.record_vulnerability(finding)
                    
        except Exception as e:
            # Some methods might not be supported, which is expected
            continue
    
    display_task_complete("HTTP Methods Testing")
    return findings