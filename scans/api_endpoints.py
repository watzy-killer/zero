"""
API Endpoints discovery module.
"""
from typing import Dict, Any, List
from urllib.parse import urljoin
from utils import log_message, display_task_start, display_task_complete
from utils.http_client import HTTPClient
import time

def run(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Test for common API endpoints.
    
    Args:
        target: Target URL to test
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of vulnerability findings
    """
    findings = test_for_api_endpoints(target, options, ctx)
    return findings


def test_for_api_endpoints(url: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Test for common API endpoints."""
    display_task_start("API Endpoints Check")
    findings = []
    
    api_paths = [
        '/api/', '/api/v1/', '/graphql', '/rest/', '/soap/',
        '/json/', '/xml/', '/oauth/', '/auth/', '/token/'
    ]
    
    client = HTTPClient(timeout=options.get('timeout', 30))
    
    for path in api_paths:
        api_url = urljoin(url, path)
        
        try:
            response = client.get(api_url)
            
            if response.status_code == 200:
                # Check for API indicators
                api_indicators = [
                    '{"', '<xml>', 'API', 'endpoint', 'GraphQL',
                    'query', 'mutation', 'subscription'
                ]
                
                if any(indicator in response.text for indicator in api_indicators):
                    finding = {
                        "type": "API Endpoint Found",
                        "severity": "Info",
                        "url": api_url,
                        "evidence": f"API endpoint found at {path}",
                        "description": "An API endpoint was discovered. APIs should be properly secured and documented.",
                        "remediation": "Implement proper authentication, authorization, and input validation for all API endpoints.",
                        "request_data": f"GET {api_url}",
                        "response_preview": response.text[:500]
                    }
                    findings.append(finding)
                    ctx.record_vulnerability(finding)
                    break
                    
        except Exception as e:
            # Skip errors for API paths that don't exist
            continue
    
    display_task_complete("API Endpoints Check")
    return findings