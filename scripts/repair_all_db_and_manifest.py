import sqlite3
import re

conn = sqlite3.connect('sentinel.db')
c = conn.cursor()

def sanitize(text: str) -> str:
    if not text:
        return text
    # First, fix known script renames
    text = text.replace("Other/xsschecker.py", "XSSscan.py")
    text = text.replace("Other/frame_audit.py", "clickjacking.py")
    text = text.replace("encryption/ssl_check.py", "ssl_check.py")
    text = text.replace("encryption/007_ssl_cipher_audit.py", "alphalowcrack.py")
    text = text.replace("encryption/019_hsts_enforce.py", "ssl_check.py")
    text = text.replace("Other/052_header_defense.py", "clickjacking.py")
    text = text.replace("Other/078_mime_sniff_probe.py", "content_type_probe.py")
    text = text.replace("scanners/banner_grab.py", "bannerscan.py")
    text = text.replace("bruteforce/028_admin_scan.py", "admin-scan.py")
    text = text.replace("bruteforce/login_probe.py", "admin-scan.py")
    text = text.replace("ircbots/003_c2_egress.py", "003_c2_egress.py")

    # Strip any remaining folder prefixes
    text = re.sub(r'\b(?:scanners|EXPLOIT|bruteforce|encryption|Other|ircbots)/', '', text)
    # If anything became Practice_Scripts/Practice_Scripts/, normalize
    text = text.replace('Practice_Scripts/Practice_Scripts/', 'Practice_Scripts/')
    return text

for table in ['technical_observations', 'scan_jobs', 'findings']:
    c.execute(f"PRAGMA table_info({table})")
    cols = [r[1] for r in c.fetchall()]
    target_cols = [col for col in cols if col in ('evidence', 'scan_metadata', 'title', 'remediation', 'description')]
    for col in target_cols:
        c.execute(f"SELECT id, {col} FROM {table} WHERE {col} IS NOT NULL")
        for rid, val in c.fetchall():
            new_val = sanitize(val)
            if new_val != val:
                c.execute(f"UPDATE {table} SET {col} = ? WHERE id = ?", (new_val, rid))

conn.commit()

c.execute("SELECT count(1) FROM technical_observations WHERE evidence LIKE '%scanners/%' OR evidence LIKE '%bruteforce/%' OR evidence LIKE '%ircbots/%' OR evidence LIKE '%encryption/%' OR evidence LIKE '%Other/%'")
print("Final technical_observations with old paths:", c.fetchone()[0])

c.execute("SELECT count(1) FROM scan_jobs WHERE scan_metadata LIKE '%scanners/%' OR scan_metadata LIKE '%bruteforce/%' OR scan_metadata LIKE '%ircbots/%' OR scan_metadata LIKE '%encryption/%' OR scan_metadata LIKE '%Other/%' OR scan_metadata LIKE '%6 modular categories%'")
print("Final scan_jobs with old paths or 6 modular categories:", c.fetchone()[0])

c.execute("SELECT count(1) FROM findings WHERE evidence LIKE '%scanners/%' OR evidence LIKE '%bruteforce/%' OR evidence LIKE '%ircbots/%' OR evidence LIKE '%encryption/%' OR evidence LIKE '%Other/%'")
print("Final findings with old paths:", c.fetchone()[0])

conn.close()
