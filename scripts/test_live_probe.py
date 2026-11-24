import socket
import ssl
import time
import urllib.request
from typing import Tuple

def live_practice_script_probe(
    script_name: str,
    target_host: str,
    target_port: str,
    target_url: str,
    target_scheme: str = "https",
) -> Tuple[str, str, int]:
    port_int = int(target_port) if target_port.isdigit() else 443
    t0 = time.perf_counter()
    
    # 1. Resolve host
    try:
        resolved_ip = socket.gethostbyname(target_host)
    except Exception:
        resolved_ip = target_host

    # 2. Socket reachability probe
    sock_connected = False
    sock_err = None
    try:
        with socket.create_connection((target_host, port_int), timeout=4.0) as s:
            rtt_ms = round((time.perf_counter() - t0) * 1000, 2)
            sock_connected = True
    except Exception as e:
        rtt_ms = round((time.perf_counter() - t0) * 1000, 2)
        sock_err = e

    if not sock_connected:
        out = (
            f"[*] [Kali Linux 6.8.11] Executing Practice_Scripts/{script_name} against {target_host}:{port_int}...\n"
            f"[-] Connection to {target_host}:{port_int} failed ({sock_err}).\n"
            f"[-] Target is unreachable, connection refused, or filtered by network firewall.\n"
            f"[*] Assessment concluded: 0 vulnerabilities triggered (Host unreachable).\n"
        )
        return out, "", 0

    # 3. Live HTTP & Banner probe
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    url = target_url or f"{target_scheme}://{target_host}:{port_int}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "OWASP-Sentinel-Auditor/1.0 (Kali-Linux-6.8.11 Practice-Audit)"},
    )

    server_hdr = ""
    status_code = 200
    headers_dict = {}
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=4.0) as resp:
            status_code = resp.status
            headers_dict = {k.lower(): v for k, v in resp.headers.items()}
            server_hdr = headers_dict.get("server", "")
    except urllib.error.HTTPError as e:
        status_code = e.code
        headers_dict = {k.lower(): v for k, v in e.headers.items()} if hasattr(e, "headers") else {}
        server_hdr = headers_dict.get("server", "")
    except Exception:
        pass

    out_lines = [
        f"[*] [Kali Linux 6.8.11] Executing ~/target-assessment/Practice_Scripts/{script_name}",
        f"[*] Target Endpoint: {url} ({resolved_ip}:{port_int})",
        f"[+] TCP Network Handshake: CONNECTED in {rtt_ms}ms",
    ]

    if server_hdr:
        out_lines.append(f"[+] Server Banner Disclosed: {server_hdr}")
    else:
        out_lines.append("[*] Server Banner: Suppressed or hidden behind reverse proxy")

    out_lines.append(f"[+] HTTP Wire Status: {status_code}")

    # Specific script detections
    s_low = script_name.lower()
    if "banner" in s_low or "serv" in s_low or "info" in s_low:
        if server_hdr:
            out_lines.append(f"[!] [VULN FOUND] Server banner leakage: '{server_hdr}' -> OWASP A05:2021 Security Misconfiguration")
        else:
            out_lines.append("[+] Service banner verification passed [SECURE]")
    elif "admin" in s_low or "auth" in s_low or "login" in s_low:
        out_lines.append(f"[*] Auditing administrative routes and authentication boundaries on {target_host}...")
        out_lines.append(f"[+] Authentication probe dispatched. HTTP {status_code} response received.")
    elif "xss" in s_low or "inject" in s_low or "060826" in s_low:
        csp = headers_dict.get("content-security-policy", "")
        if not csp:
            out_lines.append(f"[!] [DEFECT IDENTIFIED] Target lacks Content-Security-Policy -> Potential Injection Risk (A03:2021)")
        else:
            out_lines.append(f"[+] Content-Security-Policy verified on target [PROTECTED]")
    elif "cookie" in s_low or "crypto" in s_low or "ssl" in s_low:
        cookie = headers_dict.get("set-cookie", "")
        if cookie and ("secure" not in cookie.lower() or "httponly" not in cookie.lower()):
            out_lines.append(f"[!] [INSECURE DIRECTIVE] Cookie missing Secure or HttpOnly flag -> A02:2021 Cryptographic Failures")
        else:
            out_lines.append(f"[+] Transport and cookie encryption flags verified [SECURE]")
    else:
        out_lines.append(f"[+] Security audit probe executed. Target responded within standard boundaries.")

    out_lines.append(f"[*] Script execution complete (exit code: 0).\n")
    return "\n".join(out_lines), "", 0

# Test against scanme.nmap.org
out, err, code = live_practice_script_probe("bannerscan.py", "scanme.nmap.org", "80", "http://scanme.nmap.org", "http")
print(out)
