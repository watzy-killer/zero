"""
Web crawler module for discovering URLs and forms.
"""
from typing import Dict, Any, List, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import time
import re
from collections import deque
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
import time

from utils import (
    log_message, display_task_start, display_task_complete, 
    extract_links, extract_form_details, is_allowed_by_robots,
    CrawlerError
)


def run(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """
    Crawl website to discover URLs and forms for testing.
    
    Args:
        target: Target URL to crawl
        options: Scan configuration options
        ctx: Scan context object
    
    Returns:
        List of discovered URLs (vulnerability findings are recorded in context)
    """
    findings = crawl_website(target, options, ctx)
    return findings

def crawl_website(target: str, options: Dict[str, Any], ctx) -> List[Dict[str, Any]]:
    """Crawl site using Playwright to handle JavaScript."""
    display_task_start("Website Crawling")
    log_message(f"Starting JS-enabled crawl of {target}")
    
    discovered_urls = []
    max_pages = options.get('max_pages', 50)
    delay = options.get('delay', 1)
    headless = options.get('headless', True)
    
    # Check robots.txt first (using requests, not playwright)
    check_robots_txt(target, options, ctx)
    
    # FIX: Use a single controlled browser instance
    browser = None
    context = None
    page = None
    p = None
    
    try:
        # FIX: Create playwright instance
        p = sync_playwright().start()
        
        try:
            # Launch browser
            browser = p.chromium.launch(
                headless=headless,
                timeout=60000
            )
            
            # Create browser context
            context = browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                viewport={'width': 1920, 'height': 1080}
            )
            
            # Set authentication cookies
            if ctx.auth_cookies:
                context.add_cookies([{
                    'name': name,
                    'value': value,
                    'url': target
                } for name, value in ctx.auth_cookies.items()])
            
            # Create page
            page = context.new_page()
            page.set_default_timeout(60000)
            
            ctx.to_visit.append(target)
            page_count = 0

            while ctx.to_visit and page_count < max_pages:
                url = ctx.to_visit.popleft()

                if url in ctx.visited_urls:
                    continue
                    
                if not is_allowed_by_robots(url, ctx.robots_txt):
                    log_message(f"Skipping {url} (disallowed by robots.txt)")
                    continue

                try:
                    log_message(f"Crawling ({page_count+1}/{max_pages}): {url}")
                    
                    # Navigate to page
                    response = navigate_to_page(page, url)
                    if not response:
                        ctx.failed_requests.append({"url": url, "error": "Navigation failed"})
                        continue

                    # Wait for JavaScript execution
                    time.sleep(2)
                    
                    # Get page content after JavaScript execution
                    html = page.content()
                    discovered_urls.append(url)
                    ctx.visited_urls.add(url)
                    page_count += 1

                    # Extract links and forms
                    process_page_content(html, url, options, ctx)

                    time.sleep(delay)

                except Exception as e:
                    log_message(f"Error crawling {url}: {e}")
                    ctx.failed_requests.append({"url": url, "error": str(e)})
                    continue
                    
        except Exception as e:
            log_message(f"Browser setup failed: {e}")
            raise CrawlerError(f"Browser setup failed: {e}")
            
    except Exception as e:
        log_message(f"Critical error during crawling: {e}")
        raise CrawlerError(f"Crawling failed: {e}")
        
    finally:
        # FIX: PROPER CLEANUP - Close in reverse order
        try:
            if page and not page.is_closed():
                page.close()
        except Exception as e:
            log_message(f"Warning: Page close error: {e}")
            
        try:
            if context:
                context.close()
        except Exception as e:
            log_message(f"Warning: Context close error: {e}")
            
        try:
            if browser:
                browser.close()
        except Exception as e:
            log_message(f"Warning: Browser close error: {e}")
            
        try:
            if p:
                p.stop()  # FIX: Properly stop playwright
        except Exception as e:
            log_message(f"Warning: Playwright stop error: {e}")
    
    log_message(f"Crawl completed. Visited {len(ctx.visited_urls)} pages.")
    display_task_complete("Website Crawling")
    
    return discovered_urls


def check_robots_txt(target: str, options: Dict[str, Any], ctx) -> None:
    """Check for and parse robots.txt."""
    display_task_start("Robots.txt Analysis")
    robots_url = urljoin(target, '/robots.txt')
    try:
        response = ctx.session.get(robots_url, timeout=options.get('timeout', 30))
        if response.status_code == 200:
            ctx.robots_txt = response.text
            log_message(f"Found robots.txt at {robots_url}")
    except Exception as e:
        log_message(f"Error fetching robots.txt: {e}")
    display_task_complete("Robots.txt Analysis")


def navigate_to_page(page, url: str):
    """Navigate to page with robust error handling."""
    try:
        # FIX: Check if page is still usable
        if page.is_closed():
            log_message(f"Page is closed, cannot navigate to {url}")
            return None
            
        response = page.goto(url, wait_until="networkidle", timeout=60000)
        if response:
            log_message(f"HTTP Status: {response.status}")
        return response
        
    except Exception as e:
        log_message(f"Error loading {url}: {e}")
        
        # FIX: Try fallback with shorter timeout
        try:
            if not page.is_closed():
                return page.goto(url, wait_until="domcontentloaded", timeout=15000)
        except Exception as e2:
            log_message(f"Fallback also failed for {url}: {e2}")
            
        return None


def process_page_content(html: str, url: str, options: Dict[str, Any], ctx) -> None:
    """Process page content to extract links and test forms."""
    # FIX: Quick check if we should continue
    if not html or len(html) < 100:
        log_message(f"Page {url} has insufficient content, skipping form tests")
        return
        
    soup = BeautifulSoup(html, "html.parser")
    
    # Extract links
    new_links = extract_links(html, url, ctx.is_same_domain)
    for link in new_links:
        if link not in ctx.visited_urls and link not in ctx.to_visit:
            ctx.to_visit.append(link)

    # Extract and test forms (but limit to prevent overloading)
    forms = soup.find_all("form")
    log_message(f"Found {len(forms)} forms on {url}")
    
    # FIX: Limit form testing to prevent timeouts
    forms_to_test = forms[:10]  # Max 10 forms per page
    
    for form in forms_to_test:
        try:
            form_details = extract_form_details(form, url)
            if not ctx.is_same_domain(form_details['action']):
                continue
                
            # Test form for vulnerabilities
            test_form_vulnerabilities(form_details, url, options, ctx)
            
        except Exception as e:
            log_message(f"Error testing form on {url}: {e}")
            continue


def test_form_vulnerabilities(form: Dict[str, Any], page_url: str, options: Dict[str, Any], ctx) -> None:
    """Test forms for multiple vulnerability types based on selected scans."""
    
    # Get the selected scans from options
    selected_scans = options.get('selected_scans', [])
    
    # If specific scans are selected, only run those
    if selected_scans:
        if 'sql_injection' in selected_scans:
            from .sql_injection import test_sql_injection_form
            test_sql_injection_form(form, page_url, options, ctx)
        
        if 'xss' in selected_scans:
            from .xss import test_xss_form
            test_xss_form(form, page_url, options, ctx)
            
        if 'command_injection' in selected_scans:
            from .command_injection import test_command_injection_form
            test_command_injection_form(form, page_url, options, ctx)
            
        if 'path_traversal' in selected_scans:
            from .path_traversal import test_path_traversal_form
            test_path_traversal_form(form, page_url, options, ctx)
            
        if 'ssrf' in selected_scans:
            from .ssrf import test_ssrf_form
            test_ssrf_form(form, page_url, options, ctx)
            
        if 'csrf' in selected_scans:
            from .csrf import test_csrf_form
            test_csrf_form(form, page_url, options, ctx)
            
        if 'xxe' in selected_scans:
            from .xxe import test_xxe_form
            test_xxe_form(form, page_url, options, ctx)
            
        if 'ssti' in selected_scans:
            from .ssti import test_ssti_form
            test_ssti_form(form, page_url, options, ctx)
    else:
        # If no specific scans selected, run all
        from . import sql_injection, xss, command_injection, path_traversal, ssrf, csrf, xxe, ssti
        sql_injection.test_sql_injection_form(form, page_url, options, ctx)
        xss.test_xss_form(form, page_url, options, ctx)
        command_injection.test_command_injection_form(form, page_url, options, ctx)
        path_traversal.test_path_traversal_form(form, page_url, options, ctx)
        ssrf.test_ssrf_form(form, page_url, options, ctx)
        csrf.test_csrf_form(form, page_url, options, ctx)
        xxe.test_xxe_form(form, page_url, options, ctx)
        ssti.test_ssti_form(form, page_url, options, ctx)