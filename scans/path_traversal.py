"""
Path Traversal vulnerability scanner module.
"""
from typing import Dict, Any, List
from utils import log_message, display_task_start, display_task_complete
from utils.http_client import HTTPClient


def run(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Test for path traversal vulnerabilities.
    
    Args:
        target: Target URL to test
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of vulnerability findings
    """
    findings = []
    return findings  # Mainly used for form testing during crawl


def test_path_traversal_form(form: Dict[str, Any], page_url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test forms for path traversal vulnerabilities."""
    findings = []
    
    if not ctx.is_same_domain(form['action']):
        return findings
        
    display_task_start("Path Traversal Testing")
    
    test_payloads = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd'
    ]
    
    client = HTTPClient(timeout=options.get('timeout', 30))
    
    for payload in test_payloads:
        data = {}
        for input_field in form['inputs']:
            if input_field['type'] in ['text', 'textarea', 'file']:
                data[input_field['name']] = payload
            else:
                data[input_field['name']] = input_field['value']

        try:
            if form['method'] == 'post':
                response = client.post(form['action'], data=data)
            else:
                response = client.get(form['action'], params=data)

            file_indicators = [
                'root:', 'Administrator', '<?xml', '[boot loader]'
            ]
            
            if any(indicator in response.text for indicator in file_indicators):
                finding = {
                    "type": "Path Traversal",
                    "severity": "High",
                    "url": form['action'],
                    "evidence": f"Payload: {payload} may have accessed sensitive files",
                    "description": "The application may be vulnerable to path traversal attacks.",
                    "remediation": "Validate user input against whitelisted values. Use secure file access APIs.",
                    "request_data": str(data),
                    "response_preview": response.text[:500]
                }
                findings.append(finding)
                ctx.record_vulnerability(finding)
                break

        except Exception as e:
            log_message(f"Error testing path traversal on {form['action']}: {e}")
    
    display_task_complete("Path Traversal Testing")
    return findings