import json

with open('scripts/all_audit_rules.json', 'r') as fp:
    rules = json.load(fp)

print(f"Total rules: {len(rules)}")

# Count unique types
from collections import Counter
counts = Counter(r['type'] for r in rules)
for k, v in counts.items():
    print(f"  {k}: {v}")

