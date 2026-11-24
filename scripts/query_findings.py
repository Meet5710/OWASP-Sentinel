import sqlite3, json

conn = sqlite3.connect('sentinel.db')
cur = conn.cursor()
cur.execute("SELECT id, title, detection_rule_id, technical_issue_type, evidence FROM findings WHERE target_id = '2c0316f5-2f86-4784-ae84-552ed9d0a4d3' AND detection_rule_id LIKE 'KALI%' LIMIT 3")
rows = cur.fetchall()
for r in rows:
    print("=" * 60)
    print("ID:", r[0])
    print("Title:", r[1])
    print("Rule:", r[2])
    print("Type:", r[3])
    ev = json.loads(r[4])
    print("Evidence Keys:", list(ev.keys()))
    if "practical_proof" in ev:
        print("Practical Proof:")
        for pk, pv in ev["practical_proof"].items():
            print(f"  {pk}: {str(pv)[:120]}")
    if "kali_terminal_result" in ev:
        print("Kali Terminal Output:")
        print(ev["kali_terminal_result"].get("raw_terminal_output", "")[:300])
