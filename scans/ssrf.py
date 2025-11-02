"""
Server-Side Request Forgery (SSRF) vulnerability scanner module.
"""
from typing import Dict, Any, List
from utils import log_message, display_task_start, display_task_complete
from utils.http_client import HTTPClient
import time

def run(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Test for SSRF vulnerabilities.
    
    Args:
        target: Target URL to test
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of vulnerability findings
    """
    findings = []
    return findings  # Mainly used for form testing during crawl


def test_ssrf_form(form: Dict[str, Any], page_url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test forms for SSRF vulnerabilities with detailed evidence."""
    findings = []
    
    if not any(input_field['type'] in ['text', 'textarea', 'url'] for input_field in form['inputs']):
        return findings
        
    if not ctx.is_same_domain(form['action']):
        return findings
        
    display_task_start("SSRF Testing")
    
    test_payloads = [
        {"payload": "http://localhost", "description": "Localhost access attempt"},
        {"payload": "http://127.0.0.1", "description": "Loopback address access attempt"},
        {"payload": "http://169.254.169.254", "description": "AWS metadata service access attempt"},
        {"payload": "http://metadata.google.internal", "description": "GCP metadata service access attempt"},
        {"payload": "file:///etc/passwd", "description": "Local file access via file protocol"},
        {"payload": "http://internal.corporate.net", "description": "Internal network access attempt"}
    ]
    
    client = HTTPClient(timeout=options.get('timeout', 30))
    
    # Get baseline response
    try:
        baseline_data = {input_field['name']: input_field['value'] for input_field in form['inputs']}  # ✅ FIXED
        if form['method'] == 'post':
            baseline_response = client.post(form['action'], data=baseline_data)
        else:
            baseline_response = client.get(form['action'], params=baseline_data)
    except:
        baseline_response = None
    
    for test_case in test_payloads:
        payload = test_case["payload"]
        data = {}
        for input_field in form['inputs']:
            if input_field['type'] in ['text', 'textarea', 'url']:
                data[input_field['name']] = payload
            else:
                data[input_field['name']] = input_field['value']  # ✅ FIXED - removed ()

        try:
            if form['method'] == 'post':
                response = client.post(form['action'], data=data)
            else:
                response = client.get(form['action'], params=data)

            # Enhanced internal resource detection
            localhost_indicators = [
                'localhost', '127.0.0.1', 'loopback', 'local host'
            ]
            
            aws_metadata_indicators = [
                'instance-id', 'ami-id', 'hostname', 'iam/',
                'security-credentials', 'meta-data', 'user-data'
            ]
            
            internal_system_indicators = [
                'internal', 'corporate', 'intranet', 'vpn',
                '192.168.', '10.', '172.16.', '172.31.',
                'Microsoft Corp', 'Amazon.com', 'Google Cloud'
            ]
            
            file_protocol_indicators = [
                'root:', 'etc/passwd', 'C:\\Windows', '/bin/'
            ]
            
            evidence_found = None
            impact_description = ""
            resource_type = ""
            
            # Localhost access detection
            if any(indicator in response.text for indicator in localhost_indicators):
                evidence_found = f"SSRF payload accessed localhost resource"
                impact_description = "Application can make requests to internal services"
                resource_type = "localhost"
            
            # AWS metadata detection
            elif any(indicator in response.text for indicator in aws_metadata_indicators):
                evidence_found = f"SSRF payload accessed cloud metadata service"
                impact_description = "Cloud instance metadata exposed"
                resource_type = "AWS metadata"
            
            # Internal system detection
            elif any(indicator in response.text for indicator in internal_system_indicators):
                evidence_found = f"SSRF payload accessed internal network resource"
                impact_description = "Internal corporate resources accessible"
                resource_type = "internal network"
            
            # File protocol access
            elif any(indicator in response.text for indicator in file_protocol_indicators):
                evidence_found = f"SSRF payload accessed local files via file protocol"
                impact_description = "Local file system access achieved"
                resource_type = "local filesystem"
            
            # Response time analysis (potential blind SSRF)
            elif (baseline_response and 
                  response.status_code != baseline_response.status_code):
                evidence_found = f"SSRF payload caused different HTTP status"
                impact_description = "Potential blind SSRF vulnerability"
                resource_type = "unknown"
            
            if evidence_found:
                finding = {
                    "type": "Server-Side Request Forgery Vulnerability",
                    "severity": "High",
                    "url": form['action'],
                    "evidence": f"{evidence_found} using payload '{payload}'. {test_case['description']}. {impact_description}.",
                    "description": "The application is vulnerable to Server-Side Request Forgery attacks, allowing unauthorized access to internal resources and cloud metadata services.",
                    "remediation": "Validate and sanitize all user input URLs. Use allow lists for permitted domains. Implement network segmentation. Disable unnecessary URL protocols. Use cloud metadata service protection.",
                    "request_data": f"{form['method'].upper()} {form['action']} with SSRF payload: {payload}",
                    "response_preview": f"Status: {response.status_code} | Internal resource accessed: {evidence_found is not None}",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                findings.append(finding)
                ctx.record_vulnerability(finding)
                break

        except Exception as e:
            log_message(f"Error testing SSRF on {form['action']}: {e}")
    
    display_task_complete("SSRF Testing")
    return findings