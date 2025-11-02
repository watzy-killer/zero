#!/usr/bin/env python3
"""
Main Web Vulnerability Scanner orchestrator.
Discovers and runs all available vulnerability scans.
"""
import argparse
import json
import sys
import time
from typing import Dict, Any, List
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

from utils import (
    ScanContext, HTTPClient, log_message, display_scan_start, 
    display_scan_complete, display_protection_shield, ScannerError
)
from scans import get_available_scans, run_scan, crawl_website


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner')
    parser.add_argument('--target', required=True, help='Target URL to scan')
    parser.add_argument('--concurrency', type=int, default=3, 
                       help='Number of concurrent scans (default: 3)')
    parser.add_argument('--output', default='scan_report.json', 
                       help='Output JSON file (default: scan_report.json)')
    parser.add_argument('--scans', nargs='+', choices=get_available_scans(),
                       help='Specific scans to run (default: all)')
    parser.add_argument('--max-pages', type=int, default=50,
                       help='Maximum pages to crawl (default: 50)')
    parser.add_argument('--delay', type=float, default=1.0,
                       help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Request timeout in seconds (default: 30)')
    parser.add_argument('--headless', action='store_true', default=True,
                       help='Run browser in headless mode (default: True)')
    parser.add_argument('--no-crawl', action='store_true',
                       help='Skip website crawling')
    parser.add_argument('--ai', '--ai-analysis', action='store_true',
                   help='Enable AI analysis of scan results')    
    return parser.parse_args()


def setup_http_session(timeout: int = 30) -> requests.Session:
    """Set up HTTP session with common headers."""
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    })
    session.timeout = timeout
    return session


def create_scan_context(target: str, options: Dict[str, Any]) -> ScanContext:
    """Create and initialize scan context."""
    session = setup_http_session(options.get('timeout', 30))
    
    # Ensure target URL has a scheme
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    return ScanContext(
        target_url=target,
        session=session,
        auth_cookies=options.get('auth_cookies', {})
    )


def run_individual_scan(scan_name: str, target: str, options: Dict[str, Any], ctx: ScanContext) -> Dict[str, Any]:
    """Run a single scan and return results."""
    try:
        log_message(f"Starting {scan_name} scan...")
        start_time = time.time()
        
        findings = run_scan(scan_name, target, options, ctx)
        
        duration = time.time() - start_time
        log_message(f"Completed {scan_name} scan in {duration:.2f}s - Found {len(findings)} issues")
        
        return {
            'scan_name': scan_name,
            'findings': findings,
            'duration': duration,
            'success': True
        }
        
    except Exception as e:
        log_message(f"Error in {scan_name} scan: {e}", "ERROR")
        return {
            'scan_name': scan_name,
            'findings': [],
            'error': str(e),
            'success': False
        }


def run_scans_concurrently(target: str, scan_names: List[str], options: Dict[str, Any], ctx: ScanContext) -> List[Dict[str, Any]]:
    """Run multiple scans concurrently."""
    results = []
    
    with ThreadPoolExecutor(max_workers=options.get('concurrency', 3)) as executor:
        # Submit all scans
        future_to_scan = {
            executor.submit(run_individual_scan, scan_name, target, options, ctx): scan_name 
            for scan_name in scan_names
        }
        
        # Collect results as they complete
        for future in as_completed(future_to_scan):
            scan_name = future_to_scan[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                log_message(f"Scan {scan_name} failed: {e}", "ERROR")
                results.append({
                    'scan_name': scan_name,
                    'findings': [],
                    'error': str(e),
                    'success': False
                })
    
    return results


def generate_report(ctx: ScanContext, scan_results: List[Dict[str, Any]], options: Dict[str, Any]) -> Dict[str, Any]:
    """Generate comprehensive scan report."""
    scan_duration = ctx.scan_end_time - ctx.scan_start_time if ctx.scan_end_time else 0
    
    # Calculate severity counts
    severity_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Info": 0
    }
    
    for vuln in ctx.vulnerabilities:
        if vuln['severity'] in severity_counts:
            severity_counts[vuln['severity']] += 1
    
    report = {
        "scan_metadata": {
            "target": ctx.target_url,
            "scan_date": time.strftime("%Y-%m-%d"),
            "scan_start_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ctx.scan_start_time)),
            "scan_duration": f"{scan_duration:.2f} seconds",
            "pages_crawled": len(ctx.visited_urls),
            "scans_performed": [r['scan_name'] for r in scan_results],
            "options_used": options
        },
        "summary": {
            "vulnerabilities_found": len(ctx.vulnerabilities),
            "severity_breakdown": severity_counts,
            "failed_requests": len(ctx.failed_requests),
            "successful_scans": len([r for r in scan_results if r['success']]),
            "failed_scans": len([r for r in scan_results if not r['success']])
        },
        "scan_results": scan_results,
        "vulnerabilities": ctx.vulnerabilities,
        "failed_requests": ctx.failed_requests
    }
    
    return report


def save_report(report: Dict[str, Any], filename: str) -> None:
    """Save report to JSON file."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        log_message(f"Scan report saved to {filename}")
    except Exception as e:
        log_message(f"Error saving report: {e}", "ERROR")


def print_summary_report(report: Dict[str, Any]) -> None:
    """Print summary report to stdout."""
    summary = report['summary']
    vulnerabilities = report['vulnerabilities']
    
    print("\n" + "="*60)
    print("SCAN SUMMARY REPORT")
    print("="*60)
    print(f"Target: {report['scan_metadata']['target']}")
    print(f"Scan duration: {report['scan_metadata']['scan_duration']}")
    print(f"Pages crawled: {report['scan_metadata']['pages_crawled']}")
    print(f"Vulnerabilities found: {summary['vulnerabilities_found']}")
    print(f"Successful scans: {summary['successful_scans']}")
    print(f"Failed scans: {summary['failed_scans']}")
    
    print(f"\nSeverity Breakdown:")
    for severity, count in summary['severity_breakdown'].items():
        if count > 0:
            print(f"  {severity}: {count}")
    
    if vulnerabilities:
        print(f"\nVULNERABILITIES FOUND:")
        for vuln in vulnerabilities:
            print(f"[{vuln['severity']}] {vuln['type']} at {vuln['url']}")
    else:
        print(f"\nNo vulnerabilities found.")
    
    if report['failed_requests']:
        print(f"\nFailed requests: {len(report['failed_requests'])}")
    
    print("="*60)


def generate_ai_analysis(report: Dict[str, Any]) -> Dict[str, Any]:
    """Generate AI analysis for scan results."""
    try:
        from ai.gemini_analyzer import GeminiAnalyzer
        
        analyzer = GeminiAnalyzer()
        ai_result = analyzer.analyze_scan_results(report)
        
        if ai_result and ai_result.get("success"):
            report["ai_analysis"] = ai_result
            print("✅ AI analysis completed successfully!")
        else:
            print("⚠️  AI analysis skipped or failed")
            
        return report
        
    except Exception as e:
        print(f"❌ AI analysis skipped: {e}")
        return report


def main():
    """Main scanner execution function."""
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Display enhanced intro animation
        from utils.logger import display_intro
        display_intro()

        # continue with normal scan flow#
        display_protection_shield()

        # Determine which scans to run
        all_scans = get_available_scans()

        #Remove 'crawl' from automatic scans to prevent redundancy
        if 'crawl' in all_scans:
                all_scans.remove('crawl')
        scan_names = args.scans if args.scans else get_available_scans()
        log_message(f"Running {len(scan_names)} scans: {', '.join(scan_names)}")
        
        # Prepare options
        options = {
            'concurrency': args.concurrency,
            'max_pages': args.max_pages,
            'delay': args.delay,
            'timeout': args.timeout,
            'headless': args.headless,
            'no_crawl': args.no_crawl,
            'selected_scans': scan_names
        }
        
        # Create scan context
        ctx = create_scan_context(args.target, options)
        ctx.scan_start_time = time.time()
        
        # Run website crawling if not disabled
        discovered_urls = []
        if not args.no_crawl:
            try:
                discovered_urls = crawl_website(args.target, options, ctx)
                log_message(f"Discovered {len(discovered_urls)} URLs during crawling")
            except Exception as e:
                log_message(f"Crawling failed: {e}", "ERROR")
                log_message("Falling back to target-only scanning", "WARNING")
                discovered_urls = [args.target]
        else:
            discovered_urls = [args.target]
        
        # Run vulnerability scans
        log_message("Starting vulnerability scans...")
        scan_results = run_scans_concurrently(args.target, scan_names, options, ctx)
        
        # Also test each discovered URL with URL-based scanners
        if len(discovered_urls) > 1:
            log_message(f"Testing {len(discovered_urls)} discovered URLs...")
            for url in discovered_urls:
                if url != args.target:  # Don't retest the main target
                    # Run URL-based tests on each discovered page
                    run_url_based_tests(url, options, ctx)
        
        ctx.scan_end_time = time.time()
        
        # Generate and save report
        report = generate_report(ctx, scan_results, options)
        
        # AI ANALYSIS INTEGRATION
        if args.ai:
            print("\n" + "🤖" * 30)
            print("STARTING AI ANALYSIS")
            print("🤖" * 30)
            report = generate_ai_analysis(report)
        
        save_report(report, args.output)
        print_summary_report(report)
        
        # Display completion message
        from utils.logger import display_scan_complete_animation
        display_scan_complete_animation(report('vunerabilities'))
        
    except KeyboardInterrupt:
        log_message("Scan interrupted by user", "WARNING")
        sys.exit(1)
    except Exception as e:
        log_message(f"Fatal error during scan: {e}", "CRITICAL")
        sys.exit(1)


def run_url_based_tests(url: str, options: Dict[str, Any], ctx: ScanContext) -> None:
    """Run URL-based vulnerability tests on a specific URL."""
    try:
        # Import URL-based test functions
        from scans import (
            test_sql_injection_url, test_xss_url, test_xxe_url, test_ssti_url,
            test_open_redirect, test_idor, test_jwt_tampering,
            test_for_directory_listing, test_http_methods,
            test_for_admin_interfaces, test_for_api_endpoints,
            test_for_exposed_sensitive_files, test_http_security_headers
        )
        
        # Run URL-based tests
        test_sql_injection_url(url, options, ctx)
        test_xss_url(url, options, ctx)
        test_xxe_url(url, options, ctx)
        test_ssti_url(url, options, ctx)
        test_open_redirect(url, options, ctx)
        test_idor(url, options, ctx)
        test_jwt_tampering(url, options, ctx)
        test_for_directory_listing(url, options, ctx)
        test_http_methods(url, options, ctx)
        test_for_admin_interfaces(url, options, ctx)
        test_for_api_endpoints(url, options, ctx)
        test_for_exposed_sensitive_files(url, options, ctx)
        test_http_security_headers(url, options, ctx)
        
    except Exception as e:
        log_message(f"Error running URL-based tests on {url}: {e}")


if __name__ == "__main__":
    main()