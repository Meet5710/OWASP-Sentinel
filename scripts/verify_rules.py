import json

with open('scripts/all_audit_rules.json', 'r') as fp:
    rules = json.load(fp)

print(f"Loaded {len(rules)} audit rules.")
# Verify all scripts are present
rule_map = {r['script']: r for r in rules}
print(f"Unique scripts in rule_map: {len(rule_map)}")

