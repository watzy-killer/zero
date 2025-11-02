"""
Cross-Site Scripting (XSS) vulnerability scanner module.
"""
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs
from utils import log_message, display_task_start, display_task_complete
from utils.http_client import HTTPClient
import time
def run(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Test for XSS vulnerabilities in URL parameters.
    
    Args:
        target: Target URL to test
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of vulnerability findings
    """
    findings = []
    
    # Test URL parameters for XSS
    findings.extend(test_xss_url(target, options, ctx))
    
    return findings


def test_xss_url(url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test URL parameters for XSS vulnerabilities with detailed evidence."""
    display_task_start("URL XSS Testing")
    findings = []
    
    parsed = urlparse(url)
    if not parsed.query:
        return findings
        
    test_payloads = [
        {"payload": "<script>alert('XSS')</script>", "description": "Basic script tag injection"},
        {"payload": "<img src=x onerror=alert('XSS')>", "description": "Image onerror handler injection"},
        {"payload": "<svg onload=alert('XSS')>", "description": "SVG onload event injection"},
        {"payload": "javascript:alert('XSS')", "description": "JavaScript protocol handler test"},
        {"payload": "\"><script>alert('XSS')</script>", "description": "Attribute break-out injection"}
    ]
    
    client = HTTPClient(timeout=options.get('timeout', 30))
    
    # Get baseline response for comparison
    try:
        baseline_response = client.get(url)
    except:
        baseline_response = None
    
    params = parse_qs(parsed.query)
    for param_name in params.keys():
        for test_case in test_payloads:
            payload = test_case["payload"]
            test_params = params.copy()
            test_params[param_name] = payload
            new_query = "&".join([f"{k}={v}" for k, v in test_params.items()])
            test_url = url.replace(parsed.query, new_query)
            
            try:
                response = client.get(test_url)
                
                evidence_found = None
                impact_description = ""
                
                # Direct reflection detection
                if payload in response.text:
                    evidence_found = f"XSS payload was directly reflected in response"
                    impact_description = "User input not sanitized before output"
                
                # Encoded reflection detection
                elif (payload.replace('<', '&lt;') in response.text or 
                      payload.replace('>', '&gt;') in response.text):
                    evidence_found = f"XSS payload was reflected with HTML encoding"
                    impact_description = "Basic encoding applied but may be bypassed"
                
                # Script execution indicators
                elif ('alert(' in response.text and 'XSS' in response.text):
                    evidence_found = f"XSS payload triggered JavaScript execution indicators"
                    impact_description = "Potential script execution possible"
                
                # Content-type based detection
                content_type = response.headers.get('content-type', '').lower()
                if ('text/html' in content_type and 
                    any(tag in response.text for tag in ['<script>', 'onerror=', 'onload='])):
                    evidence_found = f"XSS payload injected HTML/script content"
                    impact_description = "HTML context vulnerable to injection"
                
                if evidence_found:
                    finding = {
                        "type": "Cross-Site Scripting Vulnerability",
                        "severity": "High",
                        "url": test_url,
                        "evidence": f"{evidence_found} in parameter '{param_name}'. {test_case['description']}. {impact_description}",
                        "description": "The application is vulnerable to reflected Cross-Site Scripting attacks, allowing attackers to execute malicious JavaScript in victims' browsers.",
                        "remediation": "Implement context-aware output encoding. Use Content Security Policy headers. Validate and sanitize all user input. Escape special characters in HTML context.",
                        "request_data": f"GET {test_url}",
                        "response_preview": f"Status: {response.status_code} | Content-Type: {content_type} | Payload reflection: {payload in response.text}",
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    findings.append(finding)
                    ctx.record_vulnerability(finding)
                    break  # Stop after first finding for this parameter
                    
            except Exception as e:
                log_message(f"Error testing XSS on URL {url}: {e}")
    
    display_task_complete("URL XSS Testing")
    return findings


def test_xss_form(form: Dict[str, Any], page_url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test forms for XSS vulnerabilities with detailed evidence."""
    findings = []
    
    if not ctx.is_same_domain(form['action']):
        return findings
        
    test_payloads = [
        {"payload": "<script>alert('XSS')</script>", "description": "Basic script tag injection"},
        {"payload": "<img src=x onerror=alert('XSS')>", "description": "Image onerror handler injection"},
        {"payload": "<svg onload=alert('XSS')>", "description": "SVG onload event injection"},
        {"payload": "javascript:alert('XSS')", "description": "JavaScript protocol handler test"},
        {"payload": "\"><script>alert('XSS')</script>", "description": "Attribute break-out injection"}
    ]
    
    client = HTTPClient(timeout=options.get('timeout', 30))
    
    # Get baseline response
    try:
        baseline_data = {input_field['name']: input_field['value'] for input_field in form['inputs']}
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
            if input_field['type'] == 'hidden' or input_field['value']:
                data[input_field['name']] = input_field['value']
            else:
                data[input_field['name']] = payload

        try:
            if form['method'] == 'post':
                response = client.post(form['action'], data=data)
            else:
                response = client.get(form['action'], params=data)

            evidence_found = None
            impact_description = ""
            content_type = response.headers.get('content-type', '').lower()
            
            # Direct reflection in HTML context
            if payload in response.text and 'text/html' in content_type:
                evidence_found = f"XSS payload directly reflected in HTML response"
                impact_description = "User input not sanitized, allowing script injection"
            
            # Partial reflection with script indicators
            elif any(tag in response.text for tag in ['<script>', 'onerror=', 'onload=', 'javascript:']):
                evidence_found = f"XSS payload elements reflected in response"
                impact_description = "HTML/JavaScript context vulnerable to injection"
            
            # Different response than baseline
            elif (baseline_response and 
                  response.text != baseline_response.text and
                  'text/html' in content_type):
                evidence_found = f"XSS payload altered response content"
                impact_description = "Form input affects output without sanitization"
            
            if evidence_found:
                finding = {
                    "type": "Cross-Site Scripting Vulnerability", 
                    "severity": "High",
                    "url": form['action'],
                    "evidence": f"{evidence_found} in form submission. {test_case['description']}. {impact_description}",
                    "description": "The application is vulnerable to Cross-Site Scripting attacks via form parameters, allowing attackers to execute arbitrary JavaScript in users' browsers.",
                    "remediation": "Implement context-aware output encoding. Use Content Security Policy (CSP) headers. Validate and sanitize all user input before processing. Escape special characters based on output context.",
                    "request_data": f"{form['method'].upper()} {form['action']} with XSS payload: {payload}",
                    "response_preview": f"Status: {response.status_code} | Content-Type: {content_type} | Reflection detected: {evidence_found is not None}",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                findings.append(finding)
                ctx.record_vulnerability(finding)
                break

        except Exception as e:
            log_message(f"Error testing XSS on {form['action']}: {e}")
    
    return findings