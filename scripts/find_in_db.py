import sqlite3

conn = sqlite3.connect('sentinel.db')
c = conn.cursor()

c.execute("SELECT id, target_id, scan_metadata FROM scan_jobs WHERE scan_metadata LIKE '%Route: /login%' OR scan_metadata LIKE '%Server: nginx/1.24.0%'")
rows = c.fetchall()
print('Matching scan_jobs:', len(rows))
for r in rows:
    print('Scan ID:', r[0], 'Target ID:', r[1])

c.execute("SELECT id, target_id, title FROM technical_observations WHERE evidence LIKE '%Route: /login%' OR evidence LIKE '%Server: nginx/1.24.0%'")
rows2 = c.fetchall()
print('Matching technical_observations:', len(rows2))
for r in rows2:
    print('Obs ID:', r[0], 'Target ID:', r[1], 'Title:', r[2])

conn.close()

