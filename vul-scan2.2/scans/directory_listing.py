"""
Directory Listing vulnerability scanner module.
"""
from typing import Dict, Any, List
from urllib.parse import urljoin
from utils import log_message, display_task_start, display_task_complete
from utils.http_client import HTTPClient
import time

def run(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Test for directory listing vulnerabilities.
    
    Args:
        target: Target URL to test
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of vulnerability findings
    """
    findings = test_for_directory_listing(target, options, ctx)
    return findings


def test_for_directory_listing(url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test for directory listing vulnerabilities with detailed evidence."""
    display_task_start("Directory Listing Check")
    findings = []
    
    common_directories = [
        '/admin/', '/uploads/', '/images/', '/assets/', '/js/', '/css/',
        '/backup/', '/tmp/', '/logs/', '/config/', '/include/', '/src/',
        '/database/', '/files/', '/documents/', '/media/', '/static/'
    ]
    
    client = HTTPClient(timeout=options.get('timeout', 30))
    
    for directory in common_directories:
        dir_url = urljoin(url, directory)
        
        try:
            response = client.get(dir_url)
            
            evidence_found = None
            impact_description = ""
            listing_type = ""
            
            # Check for directory listing indicators
            if response.status_code == 200:
                response_text = response.text.lower()
                
                # Apache directory listing
                if 'index of /' in response_text:
                    evidence_found = f"Apache directory listing enabled"
                    impact_description = "Directory contents publicly accessible"
                    listing_type = "Apache"
                
                # Nginx directory listing  
                elif 'directory listing' in response_text:
                    evidence_found = f"Nginx directory listing enabled"
                    impact_description = "Directory contents publicly accessible" 
                    listing_type = "Nginx"
                
                # IIS directory listing
                elif '<title>directory of' in response_text:
                    evidence_found = f"IIS directory listing enabled"
                    impact_description = "Directory contents publicly accessible"
                    listing_type = "IIS"
                
                # Generic directory listing
                elif 'parent directory' in response_text and '<a href' in response_text:
                    evidence_found = f"Generic directory listing enabled"
                    impact_description = "Directory contents publicly accessible"
                    listing_type = "Generic"
                
                # File listing detected
                elif any(file_indicator in response_text for file_indicator in ['.php', '.js', '.css', '.html', '.txt']):
                    evidence_found = f"File listing detected"
                    impact_description = "Sensitive files may be exposed"
                    listing_type = "File listing"
                
                if evidence_found:
                    finding = {
                        "type": "Directory Listing Vulnerability",
                        "severity": "Low",
                        "url": dir_url,
                        "evidence": f"{evidence_found} at path '{directory}'. {impact_description}. {listing_type} web server configuration issue.",
                        "description": "Directory listing is enabled, potentially exposing sensitive files, application structure, and configuration details to attackers.",
                        "remediation": "Disable directory listing in web server configuration. Use index files for directories. Implement proper access controls. Restrict access to sensitive directories.",
                        "request_data": f"GET {dir_url}",
                        "response_preview": f"Status: {response.status_code} | Listing type: {listing_type} | Files exposed: {evidence_found is not None}",
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    findings.append(finding)
                    ctx.record_vulnerability(finding)
                    break
                    
        except Exception as e:
            # Skip errors for directories that don't exist
            continue
    
    display_task_complete("Directory Listing Check")
    return findings