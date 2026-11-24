import json

with open('scripts/all_scripts_catalog.json', 'r') as fp:
    catalog = json.load(fp)

print(f"Total in catalog: {len(catalog)}")

samples = {}
for s in catalog:
    proto = s['proto']
    if proto not in samples:
        samples[proto] = []
    if len(samples[proto]) < 3:
        samples[proto].append(s)

for proto, slist in sorted(samples.items()):
    print(f"\n=== PROTOCOL: {proto} ({len([x for x in catalog if x['proto'] == proto])} scripts) ===")
    for s in slist:
        print(f"  - {s['file']}: {s['desc']} (ports: {s['ports']}, paths: {s['paths']}, cve: {s['cve']})")

