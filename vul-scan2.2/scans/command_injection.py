"""
Command Injection vulnerability scanner module.
"""
from typing import Dict, Any, List
from utils import log_message, display_task_start, display_task_complete
from utils.http_client import HTTPClient
import time

def run(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Test for command injection vulnerabilities.
    
    Args:
        target: Target URL to test
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of vulnerability findings
    """
    findings = []
    return findings  # Mainly used for form testing during crawl


def test_command_injection_form(form: Dict[str, Any], page_url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test forms for command injection vulnerabilities with detailed evidence."""
    findings = []
    
    if not any(input_field['type'] in ['text', 'textarea'] for input_field in form['inputs']):
        return findings
        
    if not ctx.is_same_domain(form['action']):
        return findings
        
    display_task_start("Command Injection Testing")
    
    test_payloads = [
        {"payload": "; whoami", "description": "UNIX command injection via semicolon"},
        {"payload": "| whoami", "description": "UNIX command injection via pipe"},
        {"payload": "&& whoami", "description": "UNIX command injection via AND operator"},
        {"payload": "`whoami`", "description": "UNIX command injection via backticks"},
        {"payload": "$(whoami)", "description": "UNIX command injection via dollar parentheses"},
        {"payload": "|| whoami", "description": "UNIX command injection via OR operator"},
        {"payload": "| dir C:\\", "description": "Windows command injection via pipe"},
        {"payload": "& ipconfig", "description": "Windows command injection via ampersand"}
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
            if input_field['type'] in ['text', 'textarea']:
                data[input_field['name']] = payload
            else:
                data[input_field['name']] = input_field['value']

        try:
            if form['method'] == 'post':
                response = client.post(form['action'], data=data)
            else:
                response = client.get(form['action'], params=data)

            # Enhanced command output detection
            unix_command_indicators = [
                'root', 'bin', 'daemon', 'sys', 'sync', 'games',
                'man', 'lp', 'mail', 'news', 'uucp', 'proxy',
                'www-data', 'backup', 'list', 'irc', 'gnats',
                'nobody', 'systemd', 'ubuntu', 'debian', 'centos'
            ]
            
            windows_command_indicators = [
                'Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount',
                'Microsoft Windows', 'Volume Serial Number', 'Directory of',
                'C:\\Windows', 'C:\\Users', 'C:\\Program Files'
            ]
            
            system_info_indicators = [
                'etc/passwd', '/bin/', '/usr/bin/', 'login:',
                'Volume in drive', 'Directory of', 'bytes free',
                'Windows IP Configuration', 'Ethernet adapter',
                'IPv4 Address', 'Subnet Mask', 'Default Gateway'
            ]
            
            evidence_found = None
            impact_description = ""
            detected_system = ""
            
            # UNIX system detection
            if any(indicator in response.text for indicator in unix_command_indicators):
                evidence_found = f"Command injection payload executed system commands"
                impact_description = "UNIX/Linux system commands executed successfully"
                detected_system = "UNIX/Linux"
            
            # Windows system detection  
            elif any(indicator in response.text for indicator in windows_command_indicators):
                evidence_found = f"Command injection payload executed system commands"
                impact_description = "Windows system commands executed successfully"
                detected_system = "Windows"
            
            # Generic system info leakage
            elif any(indicator in response.text for indicator in system_info_indicators):
                evidence_found = f"Command injection payload leaked system information"
                impact_description = "Sensitive system details exposed"
                detected_system = "Unknown"
            
            # Response time analysis (potential blind command injection)
            elif (baseline_response and 
                  len(response.content) > len(baseline_response.content) + 1000):
                evidence_found = f"Command injection payload caused significant response size increase"
                impact_description = "Potential blind command injection via output"
                detected_system = "Possible"
            
            if evidence_found:
                finding = {
                    "type": "Command Injection Vulnerability",
                    "severity": "Critical",
                    "url": form['action'],
                    "evidence": f"{evidence_found} using payload '{payload}'. {test_case['description']}. {impact_description} on {detected_system} system.",
                    "description": "The application is vulnerable to OS command injection attacks, allowing remote code execution on the underlying server.",
                    "remediation": "Avoid using system commands with user input. Use built-in language functions instead of shell commands. Implement strict input validation using allow lists. Use parameterized APIs for system operations.",
                    "request_data": f"{form['method'].upper()} {form['action']} with command injection payload: {payload}",
                    "response_preview": f"Status: {response.status_code} | System indicators found: {evidence_found is not None}",
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                findings.append(finding)
                ctx.record_vulnerability(finding)
                break

        except Exception as e:
            log_message(f"Error testing command injection on {form['action']}: {e}")
    
    display_task_complete("Command Injection Testing")
    return findings