"""
Helper functions for vulnerability scanning.
"""
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import re
from typing import Set, Dict, Any, List
from typing import Optional

def extract_links(html: str, base_url: str, same_domain_check) -> Set[str]:
    """Extract all links from page content."""
    links = set()
    soup = BeautifulSoup(html, "html.parser")
    
    # Standard HTML links
    for link in soup.find_all("a", href=True):
        href = link["href"].strip()
        if href and not href.startswith(('javascript:', 'mailto:', 'tel:')):
            full_url = urljoin(base_url, href)
            if same_domain_check(full_url):
                links.add(full_url)
    
    # JavaScript-based navigation
    for script in soup.find_all("script"):
        if script.string:
            js_urls = re.findall(r'["\'](https?://[^"\']+)["\']', script.string)
            for js_url in js_urls:
                if same_domain_check(js_url):
                    links.add(js_url)
    
    return links


def extract_form_details(form, base_url: str) -> Dict[str, Any]:
    """Extract details from a form with enhanced field detection."""
    details = {
        'action': urljoin(base_url, form.get('action', '')),
        'method': form.get('method', 'get').lower(),
        'inputs': [],
        'enctype': form.get('enctype', 'application/x-www-form-urlencoded')
    }

    for input_tag in form.find_all(['input', 'textarea', 'select']):
        input_details = {
            'type': input_tag.get('type', 'text'),
            'name': input_tag.get('name'),
            'value': input_tag.get('value', ''),
            'tag': input_tag.name
        }
        
        if input_tag.name == 'select':
            input_details['options'] = [
                option.get('value') for option in input_tag.find_all('option') 
                if option.get('value')
            ]
            
        if input_details['name']:
            details['inputs'].append(input_details)

    return details


def is_allowed_by_robots(url: str, robots_txt: Optional[str]) -> bool:
    """Check if URL is allowed by robots.txt."""
    if not robots_txt:
        return True
        
    for line in robots_txt.split('\n'):
        if line.startswith('Disallow:'):
            disallow_path = line.split(':', 1)[1].strip()
            if disallow_path and urlparse(url).path.startswith(disallow_path):
                return False
    return True