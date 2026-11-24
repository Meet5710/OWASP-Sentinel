import sqlite3
import json

conn = sqlite3.connect('sentinel.db')
c = conn.cursor()

c.execute("SELECT id, evidence FROM technical_observations WHERE evidence LIKE '%scanners/%' OR evidence LIKE '%bruteforce/%' LIMIT 3")
for row in c.fetchall():
    print(f"ID: {row[0]}")
    try:
        data = json.loads(row[1])
        print("Evidence keys:", list(data.keys()))
        for k in ['tool_or_script', 'verification_command', 'test_executed', 'exploit_scenario']:
            if k in data:
                print(f"  {k}: {data[k]}")
    except Exception as e:
        print("Raw evidence snippet:", row[1][:300])

c.execute("SELECT id, scan_metadata FROM scan_jobs WHERE scan_metadata LIKE '%across 6 modular categories%' LIMIT 2")
for row in c.fetchall():
    print(f"Scan ID: {row[0]}")
    try:
        data = json.loads(row[1])
        logs = data.get("terminal_logs", [])
        for l in logs:
            if "modular categories" in l.get("message", "") or "Practice_Scripts" in l.get("message", ""):
                print("  Sample log:", l)
    except Exception as e:
        print("Error:", e)

conn.close()
