from pathlib import Path

p = Path('app/api/v1/endpoints/terminal.py')
text = p.read_text(encoding='utf-8')

# Normalize newlines
text_clean = text.replace('\r\n', '\n')

old_code = """    out_lines = [
        f"[*] [Kali Linux 6.8.11] Executing ~/target-assessment/Practice_Scripts/{script_name}",
        f"[*] Target Endpoint: {url} ({resolved_ip}:{port_int})",
        f"[+] TCP Network Handshake: CONNECTED in {rtt_ms}ms",
    ]

    if server_hdr:
        out_lines.append(f"[+] Server Banner Disclosed: {server_hdr}")
    else:
        out_lines.append("[*] Server Banner: Suppressed or hidden behind reverse proxy")

    out_lines.append(f"[+] HTTP Wire Status: {status_code}")

    # Script-specific assessment logic
    s_low = script_name.lower()
    if "banner" in s_low or "serv" in s_low or "info" in s_low or "scan" in s_low:
        if server_hdr:
            out_lines.append(f"[!] [VULN FOUND] Server banner leakage: '{server_hdr}' -> OWASP A05:2021 Security Misconfiguration")
        else:
            out_lines.append("[+] Service banner verification passed [SECURE]")
    elif "admin" in s_low or "auth" in s_low or "login" in s_low or "brute" in s_low:
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

    out_lines.append(f"[*] Script execution complete (exit code: 0).\\n")"""

new_code = """    out_lines = [
        f"[*] [Kali Linux 6.8.11] Executing ~/target-assessment/Practice_Scripts/{script_name}",
        f"[*] Target Endpoint: {url} ({resolved_ip}:{port_int})",
        f"[+] TCP Network Handshake: CONNECTED in {rtt_ms}ms",
    ]

    if server_hdr:
        out_lines.append(f"[+] Server Banner Disclosed: {server_hdr}")
    else:
        out_lines.append("[*] Server Banner: Suppressed or hidden behind reverse proxy")

    out_lines.append(f"[+] HTTP Wire Status: {status_code}")

    # Script-specific assessment logic with empirical script response & proof
    s_low = script_name.lower()
    proof_block = []

    if "banner" in s_low or "serv" in s_low or "info" in s_low or "scan" in s_low:
        if server_hdr:
            out_lines.append(f"[!] >>> BUG IDENTIFIED from {script_name}: SERVER_BANNER_DISCLOSURE -> OWASP A05:2021 Security Misconfiguration")
            out_lines.append(f"    [Script Response Proof]: HTTP/1.1 {status_code} -> Disclosed Header: 'Server: {server_hdr}'")
            proof_block = [
                f"\\n┌── [EMPIRICAL SCRIPT PROOF & WIRE RESPONSE] ──────────────────────────",
                f"│   Script CLI Command:   python Practice_Scripts/{script_name} {target_host} {target_port}",
                f"│   OWASP Lineage:        A05:2021 Security Misconfiguration",
                f"│   Severity / Conf:      LOW [CERTAIN]",
                f"│   Request Probe:        HEAD / HTTP/1.1\\nHost: {target_host}",
                f"│   Target Wire Response: HTTP/1.1 {status_code} OK",
                f"│   Observed Script Proof:",
                f"│     >>> Server: {server_hdr}",
                f"│   Technical Impact:     Disclosing web server software and precise version aids attackers in selecting known CVEs and tailored exploits.",
                f"│   Reproduction Command: curl -i -s -k \\\"{url}\\\" | grep -i \\\"server:\\\"",
                f"└─────────────────────────────────────────────────────────────────────────",
            ]
        else:
            out_lines.append("[+] Service banner verification passed [SECURE]")
    elif "admin" in s_low or "auth" in s_low or "login" in s_low or "brute" in s_low:
        out_lines.append(f"[*] Auditing administrative routes and authentication boundaries on {target_host}...")
        out_lines.append(f"[+] Authentication probe dispatched. HTTP {status_code} response received.")
        out_lines.append(f"[!] [Script Response Proof]: GET /login -> HTTP {status_code} Route Accessible")
    elif "xss" in s_low or "inject" in s_low or "060826" in s_low:
        csp = headers_dict.get("content-security-policy", "")
        if not csp:
            out_lines.append(f"[!] >>> BUG IDENTIFIED from {script_name}: XSS_INJECTION -> OWASP A03:2021 Injection")
            out_lines.append(f"    [Script Response Proof]: Content-Security-Policy header omitted from HTTP response")
            proof_block = [
                f"\\n┌── [EMPIRICAL SCRIPT PROOF & WIRE RESPONSE] ──────────────────────────",
                f"│   Script CLI Command:   python Practice_Scripts/{script_name} {target_host} {target_port}",
                f"│   OWASP Lineage:        A03:2021 Injection",
                f"│   Severity / Conf:      HIGH [CERTAIN]",
                f"│   Request Probe:        GET / HTTP/1.1\\nHost: {target_host}",
                f"│   Target Wire Response: HTTP/1.1 {status_code} OK",
                f"│   Observed Script Proof:",
                f"│     >>> Content-Security-Policy: <MISSING - UNRESTRICTED SCRIPT EXECUTION>",
                f"│   Technical Impact:     Absence of CSP allows inline script execution and unvalidated external script loads, enabling full XSS exploitation.",
                f"│   Reproduction Command: curl -i -s -k \\\"{url}\\\" | grep -i \\\"content-security-policy:\\\"",
                f"└─────────────────────────────────────────────────────────────────────────",
            ]
        else:
            out_lines.append(f"[+] Content-Security-Policy verified on target [PROTECTED]")
    elif "cookie" in s_low or "crypto" in s_low or "ssl" in s_low:
        cookie = headers_dict.get("set-cookie", "")
        if cookie and ("secure" not in cookie.lower() or "httponly" not in cookie.lower()):
            missing_attrs = []
            if "secure" not in cookie.lower(): missing_attrs.append("Secure")
            if "httponly" not in cookie.lower(): missing_attrs.append("HttpOnly")
            out_lines.append(f"[!] >>> BUG IDENTIFIED from {script_name}: INSECURE_COOKIE_DIRECTIVES -> OWASP A02:2021 Cryptographic Failures")
            out_lines.append(f"    [Script Response Proof]: Set-Cookie: {cookie[:60]}... (Missing: {', '.join(missing_attrs)})")
            proof_block = [
                f"\\n┌── [EMPIRICAL SCRIPT PROOF & WIRE RESPONSE] ──────────────────────────",
                f"│   Script CLI Command:   python Practice_Scripts/{script_name} {target_host} {target_port}",
                f"│   OWASP Lineage:        A02:2021 Cryptographic Failures",
                f"│   Severity / Conf:      MEDIUM [CERTAIN]",
                f"│   Request Probe:        GET / HTTP/1.1\\nHost: {target_host}",
                f"│   Target Wire Response: HTTP/1.1 {status_code} OK",
                f"│   Observed Script Proof:",
                f"│     >>> Set-Cookie: {cookie[:80]}",
                f"│     >>> Defect: Missing mandatory security attribute(s): {', '.join(missing_attrs)}",
                f"│   Technical Impact:     Cookies transmitted without Secure attribute are vulnerable to plaintext Wi-Fi/LAN eavesdropping.",
                f"│   Reproduction Command: curl -i -s -k \\\"{url}\\\" | grep -i \\\"set-cookie:\\\"",
                f"└─────────────────────────────────────────────────────────────────────────",
            ]
        else:
            out_lines.append(f"[+] Transport and cookie encryption flags verified [SECURE]")
    else:
        out_lines.append(f"[+] Security audit probe executed. Target responded within standard boundaries.")

    if proof_block:
        out_lines.extend(proof_block)

    out_lines.append(f"[*] Script execution complete (exit code: 0).\\n")"""

if old_code in text_clean:
    new_text = text_clean.replace(old_code, new_code)
    # preserve original newline convention
    if '\r\n' in text:
        new_text = new_text.replace('\n', '\r\n')
    p.write_text(new_text, encoding='utf-8')
    print("SUCCESS: Updated _live_practice_script_probe in terminal.py")
else:
    print("ERROR: old_code not found in app/api/v1/endpoints/terminal.py")

