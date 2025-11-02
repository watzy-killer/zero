"""
Sensitive Files discovery module.
"""
from typing import Dict, Any, List
from urllib.parse import urljoin
from utils import log_message, display_task_start, display_task_complete
from utils.http_client import HTTPClient


def run(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Check for common sensitive files exposed on the server.
    
    Args:
        target: Target URL to test
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of vulnerability findings
    """
    findings = test_for_exposed_sensitive_files(target, options, ctx)
    return findings


def test_for_exposed_sensitive_files(url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Check for common sensitive files exposed on the server."""
    display_task_start("Sensitive Files Check")
    findings = []
    
    sensitive_files = [
        '/.env', '/.git/config', '/.htaccess', '/web.config',
        '/robots.txt', '/sitemap.xml', '/phpinfo.php', '/admin.php',
        '/backup.zip', '/database.sql', '/config.php', '/.DS_Store',
        '/.aws/credentials', '/docker-compose.yml', '/package.json',
        '/composer.json', '/yarn.lock', '/Gemfile'
    ]
    
    client = HTTPClient(timeout=options.get('timeout', 30))
    
    for file_path in sensitive_files:
        file_url = urljoin(url, file_path)
        
        try:
            response = client.get(file_url)
            
            if response.status_code == 200 and len(response.content) > 0:
                content_type = response.headers.get('content-type', '')
                content = response.text[:200]  # Preview first 200 chars
                
                # Check if this looks like a sensitive file
                sensitive_indicators = [
                    'DB_HOST', 'password', 'database', 'secret_key',
                    '[core]', 'repositoryformatversion', '<configuration>',
                    'AWS_ACCESS_KEY', 'AWS_SECRET_KEY', 'DATABASE_URL',
                    'API_KEY', 'SECRET_KEY', 'PRIVATE_KEY'
                ]
                
                if any(indicator in content for indicator in sensitive_indicators):
                    finding = {
                        "type": "Exposed Sensitive File",
                        "severity": "Medium",
                        "url": file_url,
                        "evidence": f"Found potentially sensitive file: {file_path}",
                        "description": "A potentially sensitive file was found exposed on the server.",
                        "remediation": "Restrict access to sensitive files. Use proper file permissions and web server configurations.",
                        "request_data": f"GET {file_url}",
                        "response_preview": content
                    }
                    findings.append(finding)
                    ctx.record_vulnerability(finding)
                    
        except Exception as e:
            # Skip errors for files that don't exist
            continue
    
    display_task_complete("Sensitive Files Check")
    return findings