"""
CSRF vulnerability scanner module.
"""
from typing import Dict, Any, List
from utils import log_message, display_task_start, display_task_complete


def run(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Test for CSRF vulnerabilities.
    
    Args:
        target: Target URL to test
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of vulnerability findings
    """
    findings = []
    return findings  # Mainly used for form testing during crawl


def test_csrf_form(form: Dict[str, Any], page_url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test forms for CSRF protection."""
    findings = []
    
    if not ctx.is_same_domain(form['action']):
        return findings
        
    display_task_start("CSRF Testing")
    
    # Check if form has CSRF token
    has_csrf_token = any(
        input_field['name'].lower() in ['csrf', 'csrfmiddlewaretoken', 'csrftoken', '_token'] 
        for input_field in form['inputs']
    )
    
    if not has_csrf_token:
        finding = {
            "type": "Potential CSRF Vulnerability",
            "severity": "Medium",
            "url": form['action'],
            "evidence": "Form missing CSRF token protection",
            "description": "The form may be vulnerable to Cross-Site Request Forgery attacks.",
            "remediation": "Implement CSRF tokens for all state-changing requests.",
            "request_data": f"Form method: {form['method']}",
            "response_preview": "No CSRF token found in form"
        }
        findings.append(finding)
        ctx.record_vulnerability(finding)
    
    display_task_complete("CSRF Testing")
    return findings