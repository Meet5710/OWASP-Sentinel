import sqlite3

conn = sqlite3.connect('sentinel.db')
c = conn.cursor()

c.execute("SELECT count(1) FROM technical_observations WHERE evidence LIKE '%scanners/%' OR evidence LIKE '%bruteforce/%' OR evidence LIKE '%ircbots/%' OR evidence LIKE '%encryption/%' OR evidence LIKE '%Other/%'")
obs_count = c.fetchone()[0]
print(f"Technical observations with old paths: {obs_count}")

c.execute("SELECT count(1) FROM scan_jobs WHERE scan_metadata LIKE '%scanners/%' OR scan_metadata LIKE '%bruteforce/%' OR scan_metadata LIKE '%ircbots/%' OR scan_metadata LIKE '%encryption/%' OR scan_metadata LIKE '%Other/%' OR scan_metadata LIKE '%6 modular categories%'")
scan_count = c.fetchone()[0]
print(f"Scan jobs with old paths or 6 modular categories: {scan_count}")

conn.close()
