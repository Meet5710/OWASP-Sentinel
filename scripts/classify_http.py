import json, os, re

with open('scripts/all_scripts_catalog.json', 'r') as fp:
    catalog = json.load(fp)

http_scripts = [s for s in catalog if s['proto'] == 'http']
print(f"Total HTTP scripts: {len(http_scripts)}")

types = {}
for s in http_scripts:
    fname = s['file'].lower()
    path = os.path.join('Practice_Scripts', s['file'])
    content = open(path, 'r', encoding='utf-8', errors='ignore').read()[:2000].lower()
    
    stype = 'web_general'
    if 'sqli' in fname or 'sql' in fname or 'injection' in content:
        stype = 'sql_injection'
    elif 'xss' in fname or 'cross site' in content:
        stype = 'xss'
    elif 'dork' in fname or 'robots' in content:
        stype = 'dork_recon'
    elif 'admin' in fname or 'login' in fname or 'auth' in fname or 'password' in fname:
        stype = 'admin_auth'
    elif 'banner' in fname or 'server' in fname or 'version' in content:
        stype = 'server_banner'
    elif 'cookie' in fname or 'session' in content:
        stype = 'cookie_session'
    elif 'cgi' in fname or 'cmd' in content or 'shell' in content:
        stype = 'cgi_command'
    elif 'cms' in fname or 'wp' in fname or 'joomla' in fname or 'vbulletin' in fname or 'drupal' in fname:
        stype = 'cms_audit'
    elif 'ssl' in fname or 'tls' in fname or 'hsts' in content:
        stype = 'ssl_crypto'
    elif 'defense' in fname or 'clickjack' in content or 'frame' in content:
        stype = 'anti_framing'
    elif 'backup' in fname or 'file' in fname or 'leak' in content or 'env' in fname:
        stype = 'sensitive_files'
    
    types[stype] = types.get(stype, 0) + 1

print("HTTP script sub-types:", json.dumps(types, indent=2))

