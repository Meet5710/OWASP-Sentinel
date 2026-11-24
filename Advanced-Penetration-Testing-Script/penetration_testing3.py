#!/usr/bin/env python3
"""
NETWATCH QUICKHACK SCANNER // Interactive Mode
A streamlined, interactive penetration testing script — Cyberpunk 2077 edition.

Jack in, choom. This is the fast-deploy version of the full Netrunner toolkit.
For deep-net operations, use scanner.py with command-line arguments.

Features:
- Interactive prompts for easy jacking in
- Quick ICE vulnerability checks
- Neon color-coded output
- Basic security breach testing

Usage:
    python penetration_testing3.py

For full Netrunner ops, use:
    python scanner.py https://target.com --full-scan
"""

import requests
import sys
import re
import concurrent.futures
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, quote
from bs4 import BeautifulSoup
from random_user_agent.user_agent import UserAgent
from random_user_agent.params import SoftwareName, OperatingSystem
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Force immediate line-buffering and UTF-8 encoding for stdout and stderr
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace", line_buffering=True)
except Exception:
    pass

# High-performance connection-pooled session for fast HTTP/HTTPS probing
SESSION = requests.Session()
adapter = requests.adapters.HTTPAdapter(pool_connections=25, pool_maxsize=25, max_retries=1)
SESSION.mount("http://", adapter)
SESSION.mount("https://", adapter)

# --- Configuration ---
VERSION = "2.0.77"

# ANSI color codes — Night City neon palette
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

def print_banner():
    """Print the Night City application banner."""
    banner = f"""
{Colors.CYAN}
    ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗   ██╗███╗   ██╗██╗  ██╗
   ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██║   ██║████╗  ██║██║ ██╔╝
   ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝██║   ██║██╔██╗ ██║█████╔╝
   ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔═══╝ ██║   ██║██║╚██╗██║██╔═██╗
   ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║     ╚██████╔╝██║ ╚████║██║  ██╗
    ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝{Colors.RESET}
{Colors.MAGENTA}╔══════════════════════════════════════════════════════════════════════════════╗
║{Colors.BOLD}{Colors.YELLOW}  ⚡ NETWATCH QUICKHACK SCANNER v{VERSION}                                    {Colors.RESET}{Colors.MAGENTA}║
║{Colors.CYAN}  >> Jacking into the Net... Stand by, choom.                               {Colors.MAGENTA}║
╠══════════════════════════════════════════════════════════════════════════════╣
║  {Colors.RED}☠  RELIC PROTOCOL WARNING{Colors.MAGENTA}                                                  ║
║  {Colors.YELLOW}This tool is for AUTHORIZED netrunning ONLY.{Colors.MAGENTA}                              ║
║  {Colors.YELLOW}Unauthorized access will flatline your rep. You assume ALL risk.{Colors.MAGENTA}          ║
║  {Colors.DIM}{Colors.CYAN}\"In Night City, you can become anyone. Just don't get caught.\"{Colors.RESET}{Colors.MAGENTA}             ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    print(banner)

def print_result(severity: str, message: str):
    """Print a neon-coded breach result."""
    colors = {
        "CRITICAL": Colors.MAGENTA,
        "HIGH": Colors.RED,
        "MEDIUM": Colors.YELLOW,
        "LOW": Colors.CYAN,
        "INFO": Colors.GREEN,
        "OK": Colors.GREEN
    }
    icons = {
        "CRITICAL": "☠ ",
        "HIGH": "⚠ ",
        "MEDIUM": "◈ ",
        "LOW": "◇ ",
        "INFO": "⊡ ",
        "OK": "✓ "
    }
    color = colors.get(severity, Colors.WHITE)
    icon = icons.get(severity, "» ")
    print(f"  {color}{icon}[{severity}]{Colors.RESET} {message}")

def print_section(title: str):
    """Print a cyberdeck module header."""
    print(f"\n{Colors.MAGENTA}{Colors.BOLD}⟫⟫ {title}{Colors.RESET}")
    print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}")

def get_user_agent() -> str:
    """Get a random user agent string."""
    software_names = [SoftwareName.CHROME.value, SoftwareName.FIREFOX.value]
    operating_systems = [OperatingSystem.WINDOWS.value, OperatingSystem.LINUX.value]
    return UserAgent(software_names=software_names, operating_systems=operating_systems).get_random_user_agent()

def make_request(url: str, method: str = "GET", data: Optional[Dict] = None, 
                 headers: Optional[Dict] = None, timeout: int = 5, 
                 allow_redirects: bool = True) -> Optional[requests.Response]:
    """Make an HTTP request with error handling using pooled session."""
    if headers is None:
        headers = {'User-Agent': get_user_agent()}
    
    try:
        if method.upper() == "GET":
            return SESSION.get(url, headers=headers, timeout=timeout, 
                               allow_redirects=allow_redirects, verify=False)
        elif method.upper() == "POST":
            return SESSION.post(url, headers=headers, data=data, 
                                timeout=timeout, verify=False)
    except requests.exceptions.RequestException as e:
        return None

def test_sql_injection(website: str, headers: Dict) -> List[str]:
    """Test for SQL injection — data fortress breach vectors."""
    print_section("DAEMON PROBE // SQL Injection")
    findings = []
    
    payloads = [
        "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--",
        "1' ORDER BY 1--", "' UNION SELECT NULL--", "admin'--"
    ]
    
    sql_errors = [
        "sql syntax", "mysql", "sqlite", "postgresql",
        "syntax error", "unclosed quotation", "ora-"
    ]
    
    parsed = urlparse(website)
    if parsed.query:
        test_params = list(parse_qs(parsed.query).keys())
    else:
        test_params = ['id', 'search', 'q', 'user']
    
    selected_payloads = payloads[:3] if not parsed.query else payloads

    def check_sqli(param: str, payload: str):
        test_url = f"{website}?{param}={quote(payload)}"
        response = make_request(test_url, headers=headers, timeout=3)
        if response:
            response_lower = response.text.lower()
            if any(err in response_lower for err in sql_errors):
                return f"Potential SQLi in parameter '{param}' with payload: {payload[:30]}"
        return None

    tasks = [(param, payload) for param in test_params for payload in selected_payloads]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        future_map = {executor.submit(check_sqli, p, pay): (p, pay) for p, pay in tasks}
        for future in concurrent.futures.as_completed(future_map):
            res = future.result()
            if res and res not in findings:
                print_result("CRITICAL", res)
                findings.append(res)
    
    if not findings:
        print_result("OK", "No obvious SQL injection vulnerabilities found")
    
    return findings

def test_xss(website: str, headers: Dict) -> List[str]:
    """Test for Cross-Site Scripting — neural interface injection."""
    print_section("QUICKHACK // Cross-Site Scripting (XSS)")
    findings = []
    
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "\"><script>alert('XSS')</script>",
        "<svg onload=alert(1)>",
        "'-alert(1)-'"
    ]
    
    parsed = urlparse(website)
    if parsed.query:
        test_params = list(parse_qs(parsed.query).keys())
    else:
        test_params = ['q', 'search', 'query']
    
    selected_payloads = payloads[:3] if not parsed.query else payloads

    def check_xss(param: str, payload: str):
        test_url = f"{website}?{param}={quote(payload)}"
        response = make_request(test_url, headers=headers, timeout=3)
        if response and payload in response.text:
            return f"Reflected XSS in parameter '{param}'"
        return None

    tasks = [(param, payload) for param in test_params for payload in selected_payloads]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        future_map = {executor.submit(check_xss, p, pay): (p, pay) for p, pay in tasks}
        for future in concurrent.futures.as_completed(future_map):
            res = future.result()
            if res and res not in findings:
                print_result("HIGH", res)
                findings.append(res)
    
    if not findings:
        print_result("OK", "No reflected XSS vulnerabilities found")
    
    return findings

def test_security_headers(website: str, headers: Dict) -> List[str]:
    """Test for missing security headers — ICE wall analysis."""
    print_section("ICE SCAN // Security Headers")
    findings = []
    
    response = make_request(website, headers=headers)
    if not response:
        return findings
    
    resp_headers = response.headers
    
    # Check important security headers
    security_headers = {
        "Content-Security-Policy": ("MEDIUM", "Missing CSP header - XSS risk"),
        "X-Frame-Options": ("MEDIUM", "Missing X-Frame-Options - Clickjacking risk"),
        "X-Content-Type-Options": ("LOW", "Missing X-Content-Type-Options"),
        "Strict-Transport-Security": ("MEDIUM", "Missing HSTS header"),
        "X-XSS-Protection": ("LOW", "Missing X-XSS-Protection"),
        "Referrer-Policy": ("LOW", "Missing Referrer-Policy"),
    }
    
    for header, (severity, message) in security_headers.items():
        if header not in resp_headers:
            print_result(severity, message)
            findings.append(message)
    
    # Check for information leakage
    if "Server" in resp_headers:
        server = resp_headers["Server"]
        if any(c.isdigit() for c in server):
            msg = f"Server header leaks version info: {server}"
            print_result("LOW", msg)
            findings.append(msg)
    
    if "X-Powered-By" in resp_headers:
        msg = f"X-Powered-By header reveals technology: {resp_headers['X-Powered-By']}"
        print_result("LOW", msg)
        findings.append(msg)
    
    if not findings:
        print_result("OK", "All major security headers present")
    
    return findings

def test_csrf(website: str, headers: Dict) -> List[str]:
    """Test for CSRF — ghost request forgery."""
    print_section("GHOST PROTOCOL // CSRF Detection")
    findings = []
    
    response = make_request(website, headers=headers)
    if not response:
        return findings
    
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form', method=re.compile('post', re.I))
    
    csrf_names = ['csrf', 'token', '_token', 'csrfmiddlewaretoken', 'authenticity_token', 'nonce']
    
    for i, form in enumerate(forms):
        has_csrf = False
        for input_tag in form.find_all('input', type='hidden'):
            name = (input_tag.get('name') or '').lower()
            if any(csrf in name for csrf in csrf_names):
                has_csrf = True
                break
        
        if not has_csrf:
            action = form.get('action', 'unknown')
            msg = f"POST form without CSRF token (action: {action})"
            print_result("MEDIUM", msg)
            findings.append(msg)
    
    if not findings:
        if forms:
            print_result("OK", f"All {len(forms)} POST forms have CSRF protection")
        else:
            print_result("INFO", "No POST forms found")
    
    return findings

def test_cookies(website: str, headers: Dict) -> List[str]:
    """Test cookie security — session chip integrity."""
    print_section("BIOCHIP SCAN // Cookie Security")
    findings = []
    
    response = make_request(website, headers=headers)
    if not response:
        return findings
    
    cookies = response.cookies
    
    if not cookies:
        print_result("INFO", "No cookies set by the server")
        return findings
    
    for cookie in cookies:
        issues = []
        
        # Check if it's a session-like cookie
        is_session = any(name in cookie.name.lower() for name in ['session', 'auth', 'token', 'login'])
        
        if not cookie.secure and website.startswith("https"):
            issues.append("missing Secure flag")
        
        if not cookie.has_nonstandard_attr('httponly'):
            issues.append("missing HttpOnly flag")
        
        samesite = cookie.get_nonstandard_attr('samesite', '').lower()
        if not samesite or samesite == 'none':
            issues.append("weak/missing SameSite")
        
        if issues:
            severity = "MEDIUM" if is_session else "LOW"
            msg = f"Cookie '{cookie.name}': {', '.join(issues)}"
            print_result(severity, msg)
            findings.append(msg)
    
    if not findings:
        print_result("OK", "All cookies have proper security attributes")
    
    return findings

def test_https(website: str) -> List[str]:
    """Test for HTTPS and SSL/TLS — encrypted link integrity."""
    print_section("CRYPTO LINK // HTTPS/TLS Verification")
    findings = []
    
    if not website.startswith("https://"):
        msg = "Site does not use HTTPS - data transmitted in plaintext"
        print_result("HIGH", msg)
        findings.append(msg)
    else:
        try:
            response = requests.get(website, verify=True, timeout=5)
            print_result("OK", "Valid SSL certificate")
        except requests.exceptions.SSLError as e:
            msg = f"SSL certificate error: {str(e)[:50]}"
            print_result("HIGH", msg)
            findings.append(msg)
        except requests.exceptions.RequestException:
            pass
    
    return findings

def test_open_redirect(website: str, headers: Dict) -> List[str]:
    """Test for open redirect — rogue reroute vectors."""
    print_section("REROUTE SCAN // Open Redirect")
    findings = []
    
    parsed = urlparse(website)
    if parsed.query:
        redirect_params = list(parse_qs(parsed.query).keys())
    else:
        redirect_params = ['redirect', 'url', 'next']
    
    evil_url = "https://evil.com"
    
    def check_redir(param: str):
        test_url = f"{website}?{param}={quote(evil_url)}"
        response = make_request(test_url, headers=headers, timeout=3, allow_redirects=False)
        if response and response.is_redirect:
            location = response.headers.get('Location', '')
            parsed_loc = urlparse(location)
            if parsed_loc.netloc in ('evil.com', 'www.evil.com') or parsed_loc.netloc.endswith('.evil.com'):
                return f"Open redirect via '{param}' parameter"
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        future_map = {executor.submit(check_redir, p): p for p in redirect_params}
        for future in concurrent.futures.as_completed(future_map):
            res = future.result()
            if res and res not in findings:
                print_result("MEDIUM", res)
                findings.append(res)
    
    if not findings:
        print_result("OK", "No open redirect vulnerabilities found")
    
    return findings

def test_directory_traversal(website: str, headers: Dict) -> List[str]:
    """Test for directory traversal — file system breach."""
    print_section("FILE BREACH // Directory Traversal")
    findings = []
    
    payloads = [
        "../../etc/passwd",
        "..%2f..%2fetc/passwd",
        "....//....//etc/passwd"
    ]
    
    parsed = urlparse(website)
    if parsed.query:
        file_params = list(parse_qs(parsed.query).keys())
    else:
        file_params = ['file', 'path', 'page']
    
    selected_payloads = payloads[:2] if not parsed.query else payloads

    def check_dt(param: str, payload: str):
        test_url = f"{website}?{param}={quote(payload)}"
        response = make_request(test_url, headers=headers, timeout=3)
        if response and "root:x:0:0" in response.text:
            return f"Directory traversal via '{param}' parameter"
        return None

    tasks = [(param, payload) for param in file_params for payload in selected_payloads]
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        future_map = {executor.submit(check_dt, p, pay): (p, pay) for p, pay in tasks}
        for future in concurrent.futures.as_completed(future_map):
            res = future.result()
            if res and res not in findings:
                print_result("HIGH", res)
                findings.append(res)
    
    if not findings:
        print_result("OK", "No directory traversal vulnerabilities found")
    
    return findings

def test_sensitive_files(website: str, headers: Dict) -> List[str]:
    """Test for exposed sensitive files — data shard recovery."""
    print_section("SHARD RECOVERY // Sensitive File Exposure")
    findings = []
    
    sensitive_paths = [
        ('/.git/HEAD', 'Git repository exposed', 'HIGH'),
        ('/.env', 'Environment file exposed', 'CRITICAL'),
        ('/phpinfo.php', 'PHP info page exposed', 'MEDIUM'),
        ('/robots.txt', 'Robots.txt found', 'INFO'),
        ('/.well-known/security.txt', 'Security.txt found', 'INFO'),
        ('/admin/', 'Admin panel accessible', 'MEDIUM'),
    ]
    
    def check_file(path: str, description: str, severity: str):
        test_url = urljoin(website, path)
        response = make_request(test_url, headers=headers, timeout=3)
        if response and response.status_code == 200:
            c_type = response.headers.get('content-type', '').lower()
            text_body = response.text
            is_html = 'text/html' in c_type or '<!doctype html' in text_body.lower() or '<html' in text_body.lower()
            
            if 'git' in path and not is_html and 'ref: refs/' in text_body:
                return (severity, description)
            elif '.env' in path and not is_html and re.search(r'^[A-Z0-9_]{2,}\s*=\s*[^\r\n]+', text_body, re.MULTILINE):
                return (severity, description)
            elif 'phpinfo' in path and ('PHP Version' in text_body or '<title>phpinfo' in text_body.lower()):
                return (severity, description)
            elif severity == 'INFO' and not is_html:
                return (severity, description)
            elif 'admin' in path and any(k in text_body.lower() for k in ['login', 'user_login', 'password']) and '<form' in text_body.lower():
                return (severity, description)
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        future_map = {executor.submit(check_file, p, d, s): (p, d, s) for p, d, s in sensitive_paths}
        for future in concurrent.futures.as_completed(future_map):
            item = future.result()
            if item:
                sev, desc = item
                print_result(sev, desc)
                findings.append(desc)
    
    if not any(f for f in findings if 'INFO' not in f):
        print_result("OK", "No critical sensitive files exposed")
    
    return findings

def test_cors(website: str, headers: Dict) -> List[str]:
    """Test CORS configuration — cross-origin breach analysis."""
    print_section("NET BREACH // CORS Misconfiguration")
    findings = []
    
    evil_origin = "https://evil.com"
    test_headers = headers.copy()
    test_headers["Origin"] = evil_origin
    
    response = make_request(website, headers=test_headers)
    
    if response:
        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '')
        
        if acao == '*':
            msg = "CORS allows any origin (*)"
            print_result("MEDIUM", msg)
            findings.append(msg)
        elif evil_origin in acao:
            if acac.lower() == 'true':
                msg = "CORS reflects arbitrary origin with credentials"
                print_result("HIGH", msg)
                findings.append(msg)
            else:
                msg = "CORS reflects arbitrary origin"
                print_result("MEDIUM", msg)
                findings.append(msg)
    
    if not findings:
        print_result("OK", "No CORS misconfigurations found")
    
    return findings

def run_quick_scan(website: str):
    """Run a quickhack security scan on the target node."""
    # Normalize URL: default to https:// for modern secure endpoints, fallback to http:// if unreachable
    if not website.startswith(('http://', 'https://')):
        test_https_url = 'https://' + website
        try:
            r = SESSION.head(test_https_url, timeout=4, verify=False)
            website = test_https_url
        except Exception:
            website = 'http://' + website
    
    print(f"\n{Colors.BOLD}{Colors.YELLOW}⚡ TARGET LOCKED: {Colors.CYAN}{website}{Colors.RESET}")
    print(f"{Colors.MAGENTA}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.DIM}  Deploying quickhack daemons... Stand by, netrunner.{Colors.RESET}")
    
    headers = {'User-Agent': get_user_agent()}
    all_findings = []
    
    # Run all breach modules concurrently for rapid, non-blocking scan execution
    tasks = [
        ("https", lambda: test_https(website)),
        ("headers", lambda: test_security_headers(website, headers)),
        ("cookies", lambda: test_cookies(website, headers)),
        ("csrf", lambda: test_csrf(website, headers)),
        ("sqli", lambda: test_sql_injection(website, headers)),
        ("xss", lambda: test_xss(website, headers)),
        ("traversal", lambda: test_directory_traversal(website, headers)),
        ("redir", lambda: test_open_redirect(website, headers)),
        ("cors", lambda: test_cors(website, headers)),
        ("files", lambda: test_sensitive_files(website, headers)),
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(fn): name for name, fn in tasks}
        for fut in concurrent.futures.as_completed(futures):
            try:
                res = fut.result()
                if res:
                    all_findings.extend(res)
            except Exception:
                pass
    
    # Mission Debrief
    print(f"\n{Colors.MAGENTA}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.YELLOW}⚡ MISSION DEBRIEF // BREACH REPORT{Colors.RESET}")
    print(f"{Colors.MAGENTA}{'═' * 60}{Colors.RESET}")
    
    # Filter out INFO findings for count
    vuln_findings = [f for f in all_findings if 'INFO' not in f]
    
    if vuln_findings:
        print(f"\n{Colors.RED}☠  {len(vuln_findings)} vulnerabilities breached the ICE:{Colors.RESET}")
        for finding in vuln_findings:
            print(f"  {Colors.YELLOW}⟫{Colors.RESET} {finding}")
    else:
        print(f"\n{Colors.GREEN}✓ ICE held. No significant breaches detected, V.{Colors.RESET}")
    
    print(f"\n{Colors.CYAN}⚡ For a deep-net run, jack in with:{Colors.RESET}")
    print(f"   {Colors.BOLD}python scanner.py {website} --full-scan{Colors.RESET}\n")
    print(f"{Colors.DIM}  \"Wake up, samurai. We have a network to burn.\"{Colors.RESET}\n")

def main():
    """Main entry point — jack into the Net."""
    print_banner()
    
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Get target from command line or prompt
    if len(sys.argv) > 1:
        website = sys.argv[1]
    else:
        print(f"{Colors.CYAN}  ⟫ Enter target node URL to breach:{Colors.RESET}")
        website = input(f"  {Colors.YELLOW}V://{Colors.RESET} ").strip()
    
    if not website:
        print(f"{Colors.RED}  ☠  Error: No target specified. Disconnecting...{Colors.RESET}")
        sys.exit(1)
    
    try:
        run_quick_scan(website)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}  ⚠ Connection severed by netrunner. Jacking out...{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}  ☠  SYSTEM MALFUNCTION: {e}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()

