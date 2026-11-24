import json, os, re

with open('scripts/all_scripts_catalog.json', 'r') as fp:
    catalog = json.load(fp)

print(f"Mapping all {len(catalog)} scripts to audit probe definitions...")

# Verify each script has:
# 1. probe_category: (http, ftp, ssh, smtp, pop3, imap, smb, dns, database, exploit, crypto)
# 2. target_port: int or None
# 3. probe_path: str or None
# 4. test_description: str
# 5. bug_type_if_vulnerable: str
# 6. owasp_lineage: str

audit_rules = []

for s in catalog:
    fname = s['file']
    fname_l = fname.lower()
    proto = s['proto']
    cve = s['cve']
    desc = s['desc']
    
    # Determine probe details
    probe = {
        'script': fname,
        'proto': proto,
        'desc': desc,
        'cve': cve,
    }
    
    if proto == 'ftp' or 'ftp' in fname_l:
        probe['type'] = 'port_service'
        probe['port'] = 21
        probe['service'] = 'FTP'
        probe['bug'] = 'EXPOSED_FTP_SERVICE'
        probe['owasp'] = ('A05:2021', 'Security Misconfiguration')
        probe['probe_msg'] = f"Auditing FTP service & authentication boundaries on port 21/TCP ({desc[:40]})..."
    elif proto == 'ssh' or 'ssh' in fname_l:
        probe['type'] = 'port_service'
        probe['port'] = 22
        probe['service'] = 'SSH'
        probe['bug'] = 'EXPOSED_SSH_SERVICE'
        probe['owasp'] = ('A07:2021', 'Identification and Authentication Failures')
        probe['probe_msg'] = f"Auditing SSH remote administration & daemon disclosures on port 22/TCP ({desc[:40]})..."
    elif proto == 'smtp' or 'smtp' in fname_l:
        probe['type'] = 'port_service'
        probe['port'] = 25
        probe['service'] = 'SMTP'
        probe['bug'] = 'EXPOSED_MAIL_RELAY'
        probe['owasp'] = ('A05:2021', 'Security Misconfiguration')
        probe['probe_msg'] = f"Auditing SMTP mail server relay & signal handling on port 25/TCP ({desc[:40]})..."
    elif proto == 'imap' or 'imap' in fname_l:
        probe['type'] = 'port_service'
        probe['port'] = 143
        probe['service'] = 'IMAP'
        probe['bug'] = 'EXPOSED_IMAP_SERVICE'
        probe['owasp'] = ('A05:2021', 'Security Misconfiguration')
        probe['probe_msg'] = f"Auditing IMAP messaging service & buffer boundaries on port 143/TCP ({desc[:40]})..."
    elif proto == 'pop3' or 'pop' in fname_l:
        probe['type'] = 'port_service'
        probe['port'] = 110
        probe['service'] = 'POP3'
        probe['bug'] = 'EXPOSED_POP3_SERVICE'
        probe['owasp'] = ('A05:2021', 'Security Misconfiguration')
        probe['probe_msg'] = f"Auditing POP3 mail access & authentication on port 110/TCP ({desc[:40]})..."
    elif proto == 'dns' or 'dns' in fname_l:
        probe['type'] = 'port_service'
        probe['port'] = 53
        probe['service'] = 'DNS'
        probe['bug'] = 'EXPOSED_DNS_SERVICE'
        probe['owasp'] = ('A05:2021', 'Security Misconfiguration')
        probe['probe_msg'] = f"Auditing DNS zone resolution & cache poisoning defenses on port 53/UDP ({desc[:40]})..."
    elif proto == 'smb' or 'smb' in fname_l:
        probe['type'] = 'port_service'
        probe['port'] = 445
        probe['service'] = 'SMB'
        probe['bug'] = 'EXPOSED_SMB_SERVICE'
        probe['owasp'] = ('A05:2021', 'Security Misconfiguration')
        probe['probe_msg'] = f"Auditing SMB network file sharing & IPC boundaries on port 445/TCP ({desc[:40]})..."
    elif proto == 'database' or 'mysql' in fname_l or 'sqlmap' in fname_l:
        probe['type'] = 'database'
        probe['port'] = 3306
        probe['service'] = 'Database'
        probe['bug'] = 'EXPOSED_DATABASE_SERVICE'
        probe['owasp'] = ('A01:2021', 'Broken Access Control')
        probe['probe_msg'] = f"Auditing database port perimeter & SQL injection vectors ({desc[:40]})..."
    elif 'banner' in fname_l or 'server' in fname_l:
        probe['type'] = 'http_banner'
        probe['bug'] = 'SERVER_BANNER_DISCLOSURE'
        probe['owasp'] = ('A05:2021', 'Security Misconfiguration')
        probe['probe_msg'] = f"Auditing server daemon banners and infrastructure disclosures ({desc[:40]})..."
    elif 'dork' in fname_l or 'robots' in fname_l:
        probe['type'] = 'http_dork'
        probe['bug'] = 'SENSITIVE_DIRECTORY_DISCLOSURE'
        probe['owasp'] = ('A01:2021', 'Broken Access Control')
        probe['probe_msg'] = f"Auditing crawler exclusions, hidden routes, and sensitive paths in robots.txt..."
    elif 'admin' in fname_l or 'login' in fname_l or 'auth' in fname_l:
        probe['type'] = 'http_admin'
        probe['bug'] = 'EXPOSED_ADMIN_INTERFACE'
        probe['owasp'] = ('A07:2021', 'Identification and Authentication Failures')
        probe['probe_msg'] = f"Auditing administrative authentication portals and login routes ({desc[:40]})..."
    elif 'cookie' in fname_l or 'crack' in fname_l or 'session' in fname_l:
        probe['type'] = 'http_cookie'
        probe['bug'] = 'INSECURE_COOKIE_DIRECTIVES'
        probe['owasp'] = ('A02:2021', 'Cryptographic Failures')
        probe['probe_msg'] = f"Auditing session cookie flags, transit protection, and cryptographic controls..."
    elif 'ssl' in fname_l or 'hsts' in fname_l:
        probe['type'] = 'http_hsts'
        probe['bug'] = 'MISSING_HSTS_HEADER'
        probe['owasp'] = ('A02:2021', 'Cryptographic Failures')
        probe['probe_msg'] = f"Validating HTTPS transport encryption and Strict-Transport-Security policy..."
    elif 'defense' in fname_l or 'clickjack' in fname_l or 'frame' in fname_l:
        probe['type'] = 'http_clickjack'
        probe['bug'] = 'MISSING_ANTI_CLICKJACKING'
        probe['owasp'] = ('A01:2021', 'Broken Access Control')
        probe['probe_msg'] = f"Evaluating anti-framing defenses and clickjacking restrictions..."
    elif 'xss' in fname_l:
        probe['type'] = 'http_xss'
        probe['bug'] = 'XSS_INJECTION'
        probe['owasp'] = ('A03:2021', 'Injection')
        probe['probe_msg'] = f"Auditing Content-Security-Policy injection defense and MIME-sniffing protection..."
    elif 'wp' in fname_l or 'wordpress' in fname_l or 'xmlrpc' in fname_l:
        probe['type'] = 'http_cms_wordpress'
        probe['bug'] = 'EXPOSED_WORDPRESS_ENDPOINT'
        probe['owasp'] = ('A05:2021', 'Security Misconfiguration')
        probe['probe_msg'] = f"Auditing WordPress CMS endpoints and XML-RPC interfaces ({desc[:40]})..."
    elif 'env' in fname_l or 'backup' in fname_l or 'acoi' in fname_l:
        probe['type'] = 'http_env'
        probe['bug'] = 'SENSITIVE_DATA_EXPOSURE'
        probe['owasp'] = ('A01:2021', 'Broken Access Control')
        probe['probe_msg'] = f"Auditing web root for exposed environment configuration files & backups..."
    elif 'cgi' in fname_l:
        probe['type'] = 'http_cgi'
        probe['bug'] = 'EXPOSED_CGI_INTERFACE'
        probe['owasp'] = ('A05:2021', 'Security Misconfiguration')
        probe['probe_msg'] = f"Auditing /cgi-bin/ scripts and remote command execution pathways..."
    elif 'sql' in fname_l or 'sqli' in fname_l:
        probe['type'] = 'http_sqli'
        probe['bug'] = 'SQL_INJECTION'
        probe['owasp'] = ('A03:2021', 'Injection')
        probe['probe_msg'] = f"Auditing parameter input validation against SQL syntax injection ({desc[:40]})..."
    elif proto == 'exploit':
        probe['type'] = 'exploit_cve'
        probe['cve'] = cve or 'CVE-REMOTE-EXPLOIT'
        probe['bug'] = 'VULNERABLE_SERVICE_DAEMON'
        probe['owasp'] = ('A06:2021', 'Vulnerable and Outdated Components')
        probe['probe_msg'] = f"Auditing remote service daemon against exploit vector ({desc[:40]})..."
    else:
        probe['type'] = 'http_endpoint'
        probe['bug'] = 'INSECURE_ENDPOINT_BEHAVIOR'
        probe['owasp'] = ('A05:2021', 'Security Misconfiguration')
        probe['probe_msg'] = f"Executing security audit check against {fname} ({desc[:40]})..."
    
    audit_rules.append(probe)

print(f"Mapped {len(audit_rules)} rules successfully.")
types_dist = {}
for r in audit_rules:
    types_dist[r['type']] = types_dist.get(r['type'], 0) + 1
print("Audit Rule Types Distribution:", json.dumps(types_dist, indent=2))

with open('scripts/all_audit_rules.json', 'w', encoding='utf-8') as fp:
    json.dump(audit_rules, fp, indent=2)
print("Saved to scripts/all_audit_rules.json")

