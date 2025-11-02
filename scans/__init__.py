"""
Vulnerability scan modules package.
"""
import importlib
import pkgutil
import os
from typing import Dict, Any, List, Callable


# Auto-discover and import all scan modules
def discover_scans() -> Dict[str, Any]:
    """Discover all available scan modules dynamically."""
    scans = {}
    package_dir = os.path.dirname(__file__)
    
    for module_info in pkgutil.iter_modules([package_dir]):
        if module_info.name.endswith('_test') or module_info.name == '__init__':
            continue
            
        try:
            module = importlib.import_module(f'.{module_info.name}', __package__)
            if hasattr(module, 'run'):
                scans[module_info.name] = module
        except ImportError as e:
            print(f"Warning: Could not import scan module {module_info.name}: {e}")
    
    return scans


# Import all scan modules
SCAN_MODULES = discover_scans()


def get_available_scans() -> List[str]:
    """Get list of available scan types."""
    return list(SCAN_MODULES.keys())


def get_scan_function(scan_name: str) -> Callable:
    """
    Get the run function for a specific scan.
    
    Args:
        scan_name: Name of the scan module
    
    Returns:
        The run function for the specified scan
    """
    if scan_name not in SCAN_MODULES:
        raise ValueError(f"Scan '{scan_name}' not found. Available scans: {get_available_scans()}")
    
    return SCAN_MODULES[scan_name].run


def run_scan(scan_name: str, target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Run a specific scan module.
    
    Args:
        scan_name: Name of the scan to run
        target: Target URL to scan
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of vulnerability findings
    """
    scan_func = get_scan_function(scan_name)
    return scan_func(target, options, ctx)


# Export commonly used functions from scan modules
from .sql_injection import test_sql_injection_form, test_sql_injection_url
from .xss import test_xss_form, test_xss_url
from .command_injection import test_command_injection_form
from .path_traversal import test_path_traversal_form
from .ssrf import test_ssrf_form
from .csrf import test_csrf_form
from .xxe import test_xxe_form, test_xxe_url
from .ssti import test_ssti_form, test_ssti_url
from .open_redirect import test_open_redirect
from .idor import test_idor
from .jwt_tampering import test_jwt_tampering
from .directory_listing import test_for_directory_listing
from .http_methods import test_http_methods
from .admin_interfaces import test_for_admin_interfaces
from .api_endpoints import test_for_api_endpoints
from .sensitive_files import test_for_exposed_sensitive_files
from .security_headers import test_http_security_headers
from .crawler import crawl_website, test_form_vulnerabilities

__all__ = [
    'SCAN_MODULES',
    'get_available_scans',
    'get_scan_function', 
    'run_scan',
    'discover_scans',
    # Export individual test functions for use by crawler
    'test_sql_injection_form',
    'test_xss_form',
    'test_command_injection_form',
    'test_path_traversal_form',
    'test_ssrf_form',
    'test_csrf_form',
    'test_xxe_form',
    'test_ssti_form',
    'test_sql_injection_url',
    'test_xss_url',
    'test_xxe_url',
    'test_ssti_url',
    'test_open_redirect',
    'test_idor',
    'test_jwt_tampering',
    'test_for_directory_listing',
    'test_http_methods',
    'test_for_admin_interfaces',
    'test_for_api_endpoints',
    'test_for_exposed_sensitive_files',
    'test_http_security_headers',
    'crawl_website',
    'test_form_vulnerabilities'
]