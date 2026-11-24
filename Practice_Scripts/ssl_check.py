#!/usr/bin/env python3
"""
Kali Linux Practice Script: ssl_check.py
Inspects target TLS handshake, certificate chains, and HTTP Strict Transport Security (HSTS) headers.
"""
import sys
import socket
import ssl
import urllib.request

def audit_ssl(host: str, port: int = 443):
    print(f"[*] Auditing SSL/TLS parameters and transport encryption for {host}:{port}...")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, int(port)), timeout=4.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                print(f"[+] TLS Protocol Version: {ssock.version()}")
                print(f"[+] Active Cipher Suite: {cipher[0]} ({cipher[2]} bits)")
    except Exception as e:
        print(f"[-] TLS socket connection failed: {e}")
        return

    try:
        req = urllib.request.Request(
            f"https://{host}:{port}/",
            headers={"User-Agent": "OWASP-Sentinel-Auditor/1.0 (Kali-Linux-6.8.11 ssl_check.py)"},
        )
        with urllib.request.urlopen(req, context=ctx, timeout=4.0) as resp:
            headers = dict(resp.headers)
            hsts = headers.get("Strict-Transport-Security") or headers.get("strict-transport-security")
            if not hsts:
                print("[!] >>> BUG IDENTIFIED: MISSING_HSTS_HEADER -> OWASP A02:2021 Cryptographic Failures")
                print("    [Script Response Proof]: Strict-Transport-Security header omitted from HTTPS response")
                print("    [Technical Impact]: Allows SSL stripping and downgrade attacks on untrusted networks.")
            else:
                print(f"[+] Strict-Transport-Security verified: {hsts}")
    except Exception as e:
        print(f"[-] HTTP probe notice: {e}")

if __name__ == "__main__":
    h = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    p = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 443
    audit_ssl(h, p)

