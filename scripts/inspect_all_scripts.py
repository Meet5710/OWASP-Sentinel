import os, re, json

files = sorted(os.listdir('Practice_Scripts'))
print(f'Inspecting {len(files)} scripts...')

script_info = []

for f in files:
    path = os.path.join('Practice_Scripts', f)
    with open(path, 'r', encoding='utf-8', errors='ignore') as fp:
        content = fp.read()
    
    # Extract comments / title
    lines = content.splitlines()
    header_lines = [l.strip('#/ \t') for l in lines[:20] if l.strip().startswith('#') and len(l.strip('#/ \t')) > 5]
    desc = header_lines[0] if header_lines else f'Practice Script {f}'
    
    # Detect target port
    ports = []
    found_ports = re.findall(r'port\s*=\s*(\d+)', content, re.IGNORECASE)
    if found_ports:
        ports.extend(found_ports)
    found_conn = re.findall(r'connect\(\(.*?,.*?(\d+)\)', content)
    if found_conn:
        ports.extend(found_conn)
    
    # Detect protocol / type
    proto = 'http'
    desc_l = desc.lower()
    f_l = f.lower()
    content_l = content[:2000].lower()
    
    if 'ftp' in f_l or '21' in ports or 'ftp' in desc_l:
        proto = 'ftp'
    elif 'ssh' in f_l or '22' in ports or 'ssh' in desc_l:
        proto = 'ssh'
    elif 'smtp' in f_l or '25' in ports or 'mail' in desc_l or 'sendmail' in desc_l:
        proto = 'smtp'
    elif 'imap' in f_l or '143' in ports or 'worldmail' in desc_l or 'mdaemon' in desc_l:
        proto = 'imap'
    elif 'pop' in f_l or '110' in ports:
        proto = 'pop3'
    elif 'dns' in f_l or '53' in ports:
        proto = 'dns'
    elif 'smb' in f_l or '445' in ports or '139' in ports:
        proto = 'smb'
    elif 'sql' in f_l or 'mysql' in f_l or '3306' in ports:
        proto = 'database'
    elif 'irc' in f_l or '6667' in ports:
        proto = 'irc'
    elif any(k in f_l for k in ['xss', 'sql', 'dork', 'admin', 'http', 'web', 'banner', 'url', 'cgi', 'cookie', 'ssl', 'php', 'asp']):
        proto = 'http'
    elif 'cve' in content_l or 'overflow' in content_l or 'exploit' in content_l:
        proto = 'exploit'
    
    # Detect paths tested if http
    paths = re.findall(r'["\'](/[-a-zA-Z0-9_./?=&]+)["\']', content)
    http_paths = [p for p in paths if p.startswith('/') and len(p) > 2 and not p.startswith('//') and not p.endswith('.py')][:3]
    
    # Check if there is CVE or advisory
    cve_match = re.findall(r'(CVE-\d{4}-\d+|bid/\d+|bid\s*:\s*\d+)', content, re.IGNORECASE)
    
    script_info.append({
        'file': f,
        'proto': proto,
        'desc': desc[:70],
        'ports': ports[:2],
        'paths': http_paths,
        'cve': cve_match[0] if cve_match else ''
    })

print(f'Total analyzed: {len(script_info)}')
proto_counts = {}
for s in script_info:
    proto_counts[s['proto']] = proto_counts.get(s['proto'], 0) + 1
print('Protocol counts:', json.dumps(proto_counts, indent=2))

with open('scripts/all_scripts_catalog.json', 'w', encoding='utf-8') as out_fp:
    json.dump(script_info, out_fp, indent=2)
print('Saved to scripts/all_scripts_catalog.json')

