import sqlite3
import re

conn = sqlite3.connect('sentinel.db')
c = conn.cursor()

c.execute("SELECT id, evidence FROM technical_observations WHERE evidence LIKE '%scanners/%' OR evidence LIKE '%bruteforce/%' OR evidence LIKE '%ircbots/%' OR evidence LIKE '%encryption/%' OR evidence LIKE '%Other/%' LIMIT 5")
for rid, ev in c.fetchall():
    print(f"Obs {rid}:")
    for m in re.finditer(r'[a-zA-Z0-9_\-\.\/]{0,30}(?:scanners|bruteforce|ircbots|encryption|Other)\/[a-zA-Z0-9_\-\.\/]{0,30}', ev):
        print("  Match:", m.group(0))

c.execute("SELECT id, scan_metadata FROM scan_jobs WHERE scan_metadata LIKE '%scanners/%' OR scan_metadata LIKE '%bruteforce/%' OR scan_metadata LIKE '%ircbots/%' OR scan_metadata LIKE '%encryption/%' OR scan_metadata LIKE '%Other/%' OR scan_metadata LIKE '%6 modular categories%' LIMIT 5")
for rid, sm in c.fetchall():
    print(f"Scan {rid}:")
    for m in re.finditer(r'[a-zA-Z0-9_\-\.\/]{0,30}(?:scanners|bruteforce|ircbots|encryption|Other)\/[a-zA-Z0-9_\-\.\/]{0,30}', sm):
        print("  Match in scan:", m.group(0))

conn.close()
