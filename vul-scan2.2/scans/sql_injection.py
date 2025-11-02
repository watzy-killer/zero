"""
SQL Injection vulnerability scanner module.
"""
from typing import Dict, Any, List
from urllib.parse import urlparse
from utils import log_message, display_task_start, display_task_complete
from utils.http_client import HTTPClient
import time

def run(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Test for SQL injection vulnerabilities in forms and URL parameters.
    
    Args:
        target: Target URL to test
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of vulnerability findings
    """
    findings = []
    
    # Test URL parameters for SQL injection
    findings.extend(test_sql_injection_url(target, options, ctx))
    
    return findings


def test_sql_injection_url(url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test URL parameters for SQL injection vulnerabilities with detailed evidence."""
    display_task_start("URL SQL Injection Testing")
    findings = []
    
    parsed = urlparse(url)
    if not parsed.query:
        return findings
        
    test_payloads = [
        {"payload": "'", "description": "Single quote syntax test"},
        {"payload": "' OR '1'='1", "description": "Basic authentication bypass"},
        {"payload": "' UNION SELECT NULL--", "description": "Union-based injection test"},
        {"payload": "' AND 1=CONVERT(int,@@version)--", "description": "Database version extraction"}
    ]
    
    client = HTTPClient(timeout=options.get('timeout', 30))
    
    for test_case in test_payloads:
        payload = test_case["payload"]
        test_url = url.replace(parsed.query, f"{parsed.query}{payload}", 1)
        
        try:
            response = client.get(test_url)
            original_response = client.get(url)  # Get baseline for comparison
            
            # Check for SQL error responses
            error_indicators = [
                'sql', 'syntax', 'mysql', 'ora-', 'postgresql', 
                'odbc', 'database', 'query failed', 'you have an error'
            ]
            
            # Check for authentication bypass indicators
            auth_bypass_indicators = [
                'welcome', 'dashboard', 'admin', 'logout', 'session',
                'login successful', 'access granted'
            ]
            
            evidence_found = None
            impact_description = ""
            
            # Detect based on error messages
            if any(error in response.text.lower() for error in error_indicators):
                evidence_found = f"SQLi payload '{payload}' triggered database error message"
                impact_description = "Database errors exposed in response"
            
            # Detect authentication bypass
            elif (response.status_code == 200 and original_response.status_code == 401):
                evidence_found = f"SQLi payload '{payload}' resulted in authentication bypass (401 → 200)"
                impact_description = "Authentication mechanism vulnerable to bypass"
            
            # Detect content difference (potential blind SQLi)
            elif (response.status_code == 200 and 
                  len(response.content) > 0 and 
                  response.text != original_response.text):
                evidence_found = f"SQLi payload '{payload}' caused different response content"
                impact_description = "Application behavior altered by SQL injection"
            
            if evidence_found:
                finding = {
                    "type": "SQL Injection Vulnerability",
                    "severity": "Critical",
                    "url": test_url,
                    "evidence": f"{evidence_found}. {test_case['description']}. {impact_description}",
                    "description": "The application is vulnerable to SQL injection attacks, allowing unauthorized database access or authentication bypass.",
                    "remediation": "Implement parameterized queries/prepared statements. Validate and sanitize all user inputs. Use ORM frameworks with built-in protection.",
                    "request_data": f"GET {test_url}",
                    "response_preview": f"Status: {response.status_code} | Size: {len(response.content)} bytes | Headers: {dict(response.headers)}",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                findings.append(finding)
                ctx.record_vulnerability(finding)
                break  # Stop after first finding
                
        except Exception as e:
            log_message(f"Error testing SQLi on URL {url}: {e}")
    
    display_task_complete("URL SQL Injection Testing")
    return findings


def test_sql_injection_form(form: Dict[str, Any], page_url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test forms for SQL injection vulnerabilities with detailed evidence."""
    findings = []
    
    if not ctx.is_same_domain(form['action']):
        return findings
        
    test_payloads = [
        {"payload": "'", "description": "Single quote syntax test"},
        {"payload": "' OR '1'='1", "description": "Basic authentication bypass"}, 
        {"payload": "' UNION SELECT NULL--", "description": "Union-based injection"},
        {"payload": "'; EXEC xp_cmdshell('dir')--", "description": "Command execution test"},
        {"payload": "' AND 1=CONVERT(int,@@version)--", "description": "Database version extraction"}
    ]
    
    client = HTTPClient(timeout=options.get('timeout', 30))
    
    # Get baseline response
    try:
        if form['method'] == 'post':
            baseline_data = {input_field['name']: input_field['value'] for input_field in form['inputs']}
            baseline_response = client.post(form['action'], data=baseline_data)
        else:
            baseline_data = {input_field['name']: input_field['value'] for input_field in form['inputs']}
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

            # Enhanced detection logic
            error_indicators = [
                'sql', 'syntax', 'mysql', 'ora-', 'postgresql', 'odbc', 
                'database', 'query failed', 'you have an error'
            ]
            
            evidence_found = None
            impact_description = ""
            
            # Error-based detection
            if any(error in response.text.lower() for error in error_indicators):
                evidence_found = f"SQLi payload '{payload}' triggered database error"
                impact_description = "Database errors exposed to attackers"
            
            # Behavioral difference detection
            elif (baseline_response and 
                  response.status_code != baseline_response.status_code):
                evidence_found = f"SQLi payload '{payload}' changed response status ({baseline_response.status_code} → {response.status_code})"
                impact_description = "Application behavior altered by SQL injection"
            
            # Content length difference (blind SQLi indicator)
            elif (baseline_response and 
                  len(response.content) != len(baseline_response.content)):
                evidence_found = f"SQLi payload '{payload}' caused different response size"
                impact_description = "Potential blind SQL injection vulnerability"
            
            if evidence_found:
                finding = {
                    "type": "SQL Injection Vulnerability",
                    "severity": "Critical",
                    "url": form['action'],
                    "evidence": f"{evidence_found} in form submission. {test_case['description']}. {impact_description}",
                    "description": "The application is vulnerable to SQL injection attacks via form parameters, allowing database manipulation or authentication bypass.",
                    "remediation": "Use parameterized queries/prepared statements. Implement input validation and sanitization. Apply principle of least privilege to database accounts.",
                    "request_data": f"{form['method'].upper()} {form['action']} with payload: {payload}",
                    "response_preview": f"Status: {response.status_code} | Headers: {dict(response.headers)}",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                findings.append(finding)
                ctx.record_vulnerability(finding)
                break

        except Exception as e:
            log_message(f"Error testing SQLi on {form['action']}: {e}")
    
    return findings