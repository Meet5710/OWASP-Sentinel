# ⚡ NetWatch Advanced Breach Scanner v2.0 // Cyberpunk 2077 Edition

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0.77-ff00ff.svg?style=flat-square&logo=hackthebox&logoColor=white" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.8+-00f0ff.svg?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-fcee09.svg?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Night_City-2077-ff003c.svg?style=flat-square" alt="Night City">
</p>

<p align="center">
  <em>"In 2077, what makes someone a criminal? Getting caught."</em>
</p>

A comprehensive, high-tech netrunner toolkit for authorized security assessments. Jack into any target node with extensive ICE-breaking capabilities for web applications, APIs, and network services. Welcome to Night City, choom.

## ☠ Relic Protocol Warning

**This tool is for AUTHORIZED netrunning ONLY.**

Using this tool against systems without explicit permission from the owner is a **CAPITAL OFFENSE in Night City**. The netrunner assumes all responsibility for any actions performed using this toolkit. Don't flatline your rep.

## ⚡ Features

### 🔍 Recon // Net Scanning
- **Web Crawling**: Automated URL discovery with configurable spider daemons
- **Technology Fingerprinting**: Detect CMS, frameworks, and server tech stacks
- **Subdomain Enumeration**: Deep-net subdomain recon via DNS resolution
- **Port Scanning**: Map open service ports across target nodes
- **JavaScript Analysis**: Extract API endpoints from JS file shards

### 💉 Quickhack // Injection Modules
- **SQL Injection**: Error-based and time-based blind SQLi daemon probes
- **Cross-Site Scripting (XSS)**: Reflected and DOM-based neural interface injection
- **Command Injection**: OS command injection — direct braindance to shell
- **LDAP Injection**: LDAP query manipulation breach testing
- **Server-Side Template Injection (SSTI)**: Template engine exploitation
- **XML External Entity (XXE)**: XML parser vulnerability quickhacks

### 🔐 ICE Breaker // Auth & Access
- **CSRF Testing**: Cross-Site Request Forgery ghost protocol detection
- **Weak Credentials**: Default/common password brute force
- **JWT Security**: Biochip token analysis and algorithm verification
- **Session Management**: Cookie security and session chip integrity

### 🌐 Net Protocol // API Security
- **REST API Testing**: Common API vulnerability breach checks
- **GraphQL Security**: Introspection and query batching exploits
- **CORS Misconfiguration**: Cross-origin resource sharing breach analysis
- **Rate Limiting**: Brute force ICE protection detection

### 🛡️ Firewall // Security Headers & Config
- **HTTP Security Headers**: CSP, HSTS, X-Frame-Options, etc.
- **TLS/SSL Analysis**: Certificate and cipher suite verification
- **Cookie Security**: Secure, HttpOnly, SameSite chip attributes
- **Information Disclosure**: Sensitive data shard exposure detection

### 📊 Data Shards // Reporting
- **JSON Reports**: Machine-readable data shard output
- **HTML Reports**: Neon-styled interactive breach reports
- **Console Output**: Color-coded real-time netrunner feed
- **Severity Classification**: CRITICAL, HIGH, MEDIUM, LOW, INFO

## 🚀 Installation // Jack In

```bash
# Clone the repository
git clone https://github.com/MiChaelinzo/Advanced-Penetration-Testing-Script.git

# Navigate to the directory
cd Advanced-Penetration-Testing-Script

# Install dependencies — load your cyberdeck
pip install -r requirements.txt
```

## 📖 Usage // Netrunner Operations

### Quickhack Mode (Interactive)
```bash
python penetration_testing3.py
```
Or with target node:
```bash
python penetration_testing3.py https://example.com
```

### Full Netrunner Protocol (Command Line)

#### Quick Recon Run
```bash
python scanner.py https://example.com
```

#### Full Breach Protocol
```bash
python scanner.py https://example.com --full-scan
```

#### Custom Operations
```bash
# Deep-net recon with port scan and subdomain enumeration
python scanner.py https://example.com --scan-ports --enum-subdomains

# Export HTML data shard
python scanner.py https://example.com -o report.html --format html

# Use custom quickhack payload files
python scanner.py https://example.com --sqli-payloads sqli.txt --xss-payloads xss.txt

# Bypass SSL ICE
python scanner.py https://self-signed.local --no-verify-ssl

# Verbose netrunner output
python scanner.py https://example.com -v --full-scan
```

### Command Line Options

```
Target:
  url                   Target node URL (e.g., https://example.com)

Scan Options:
  --full-scan           Enable full netrunner protocol — all modules
  --crawl               Enable web spider daemon (default: enabled)
  --no-crawl            Disable web spider daemon
  --crawl-depth N       Maximum spider depth (default: 2)
  --max-pages N         Maximum nodes to crawl (default: 50)
  --scan-ports          Enable port mapping
  --enum-subdomains     Enable deep-net subdomain recon
  --test-creds          Test for weak credentials (default: enabled)
  --no-test-creds       Disable credential brute force

Payload Files:
  --sqli-payloads FILE  Custom SQL injection quickhack payloads
  --xss-payloads FILE   Custom XSS quickhack payloads
  --dir-payloads FILE   Custom directory traversal payloads
  --username-list FILE  Custom usernames for credential testing
  --password-list FILE  Custom passwords for credential testing

Output Options:
  -o, --output FILE     Output file for data shard report
  --format {json,html}  Report format (default: json)
  -v, --verbose         Enable verbose netrunner output
  -q, --quiet           Minimal output — stealth mode

Connection Options:
  --no-verify-ssl       Disable SSL ICE verification
  --timeout N           Request timeout in seconds (default: 10)
  --threads N           Number of concurrent daemon threads (default: 10)
```

## 📁 Project Structure // Cyberdeck Layout

```
Advanced-Penetration-Testing-Script/
├── scanner.py              # Full netrunner breach scanner
├── penetration_testing3.py # QuickHack interactive scanner
├── requirements.txt        # Cyberdeck dependencies
├── README.md               # Netrunner documentation
├── LICENSE                 # MIT License
└── .github/
    ├── FUNDING.yml
    └── ISSUE_TEMPLATE/
```

## 🔧 Breach Modules // Quickhack Library

| Module | Quickhacks |
|--------|-----------|
| **Injection** | SQL Injection, XSS, Command Injection, LDAP Injection, SSTI, XXE |
| **Auth Bypass** | CSRF, Weak Credentials, Broken Session Management |
| **ICE Analysis** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| **Crypto Link** | Certificate Validation, Protocol Version, Cipher Strength |
| **Net Protocol** | CORS, GraphQL Introspection, JWT Analysis, Rate Limiting |
| **Data Shards** | Directory Traversal, Sensitive Files, Debug Mode |
| **Other** | Clickjacking, Open Redirect, Insecure File Upload, SSRF |

## 📋 Example Output

```
   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗ ██╗   ██╗███╗   ██╗██╗  ██╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██║   ██║████╗  ██║██║ ██╔╝
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝██║   ██║██╔██╗ ██║█████╔╝
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██╔═══╝ ██║   ██║██║╚██╗██║██╔═██╗
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║     ╚██████╔╝██║ ╚████║██║  ██╗
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝

╔══════════════════════════════════════════════════════════════════════════════╗
║  ⚡ NETWATCH ADVANCED BREACH SCANNER v2.0.77                                ║
║  >> Night City's Premier Netrunner Toolkit                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝

⚡ Jacking into target node: https://example.com

⟫⟫ PHASE 1: RECON // Scanning the Net
────────────────────────────────────────
  Fingerprinting node technologies...
    ✓ Detected: Nginx
    ✓ Detected: PHP
  Deploying spider daemons...
    Discovered 25 URLs, 8 JS file shards

⟫⟫ PHASE 2: BREACH PROTOCOL // Deploying Quickhacks
────────────────────────────────────────
  DAEMON PROBE // SQL Injection...
  QUICKHACK // XSS...
  ICE SCAN // Security Headers...
    [MEDIUM] Missing ICE layer — CSP

═══════════════════════════════════════════════════════
⚡ BREACH REPORT // SCAN RESULTS
═══════════════════════════════════════════════════════

◈ Breach Summary:
   ☠  CRITICAL: 0
   ⚠  HIGH: 1
   ◈  MEDIUM: 3
   ◇  LOW: 5
   ⊡  INFO: 2
   ⟫  TOTAL: 11

⚡ HTML data shard saved to: report.html
```

## 🤝 Contributing // Join the Crew

We welcome contributions from fellow netrunners! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/nova-quickhack`)
3. Commit your changes (`git commit -m 'Add nova quickhack module'`)
4. Push to the branch (`git push origin feature/nova-quickhack`)
5. Open a Pull Request

### Areas for Contribution
- Additional quickhack / vulnerability modules
- Improved ICE detection accuracy
- Performance optimizations — faster breach times
- Documentation improvements
- Bug fixes and daemon stability

## 📜 Disclaimer

This project is for **educational and authorized security testing purposes only**.

- Always obtain proper authorization before testing any system
- Do not use this tool against systems you don't own or have permission to test
- The authors are not responsible for any misuse or damage caused by this tool
- This tool should not be used in a production environment without proper validation
- *"In Night City, you can become anyone. Just don't get caught."*

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🌟 Changelog // Patch Notes

### v2.0.77 (2077 Edition)
- Cyberpunk 2077 themed UI — neon Night City aesthetics
- Netrunner terminology throughout (ICE, daemons, quickhacks, data shards)
- Neon-styled HTML breach reports with Orbitron & Share Tech Mono fonts
- ASCII art CYBERPUNK banner
- Cyberpunk severity icons and section headers

### v2.0.0 (2024)
- Complete rewrite with modern Python practices
- Added async/concurrent scanning
- Added web crawling and URL discovery
- Added technology fingerprinting
- Added subdomain enumeration
- Added port scanning
- Added SSTI, XXE, LDAP injection testing
- Added JWT security analysis
- Added GraphQL security testing
- Added API security testing
- Added CORS testing
- Added HTML report generation
- Improved detection accuracy
- Color-coded console output
- Comprehensive documentation

### v1.0.0 (2023)
- Initial release
- Basic vulnerability testing
- SQL injection, XSS, CSRF testing
- Cookie security analysis
- HTTP header checks

---

<p align="center">
  <em>Made with ☠ for the netrunner community — Night City, 2077</em>
</p>

<p align="center">
  <em>"Wake up, samurai. We have a network to burn."</em>
</p>

![Cyberpunk Security](https://user-images.githubusercontent.com/68110223/216805944-5500f5b8-883f-4621-876a-d8c9da678813.png)
