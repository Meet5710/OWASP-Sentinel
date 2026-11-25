"""OWASP Sentinel - Database Viewer Utility

Inspect tables, row counts, and query records in tabular format.
Usage:
    python view_db.py                  # Summary of all tables and row counts
    python view_db.py findings         # View findings table (latest first)
    python view_db.py assets           # View registered target assets
    python view_db.py <table_name>     # View any table
"""

import sqlite3
import sys
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "sentinel.db"


def format_table(headers: list[str], rows: list[tuple], max_col_width: int = 40) -> str:
    """Format headers and rows into a clean ASCII table."""
    if not rows:
        return "(Table is empty - 0 rows)"

    str_rows = []
    for r in rows:
        str_rows.append([
            (str(val) if val is not None else "NULL")[:max_col_width]
            for val in r
        ])

    col_widths = [len(h) for h in headers]
    for row in str_rows:
        for idx, val in enumerate(row):
            if idx < len(col_widths):
                col_widths[idx] = max(col_widths[idx], len(val))
            else:
                col_widths.append(len(val))

    # Format header
    sep = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    header_row = "| " + " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers)) + " |"

    lines = [sep, header_row, sep]
    for row in str_rows:
        r_str = "| " + " | ".join(val.ljust(col_widths[i]) for i, val in enumerate(row)) + " |"
        lines.append(r_str)
    lines.append(sep)

    return "\n".join(lines)


def show_summary(conn: sqlite3.Connection):
    """Show all tables and their row counts."""
    cur = conn.cursor()
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;"
    )
    tables = [r[0] for r in cur.fetchall()]

    print("\n" + "=" * 65)
    print("           OWASP SENTINEL DATABASE (sentinel.db) SUMMARY          ")
    print("=" * 65)

    rows = []
    for t in tables:
        count = cur.execute(f"SELECT COUNT(*) FROM \"{t}\";").fetchone()[0]
        cur.execute(f"PRAGMA table_info(\"{t}\");")
        cols = [c[1] for c in cur.fetchall()]
        rows.append((t, str(count), f"{len(cols)} columns: " + ", ".join(cols[:4]) + ("..." if len(cols) > 4 else "")))

    print(format_table(["Table Name", "Row Count", "Columns Sample"], rows, max_col_width=45))
    print("\n💡 Tip: To view records inside any table, run:")
    print("       python view_db.py <table_name>   (e.g., python view_db.py findings)\n")


def show_table(conn: sqlite3.Connection, table_name: str, limit: int = 25):
    """Show records inside a specific table."""
    cur = conn.cursor()

    # Validate table exists
    cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=? COLLATE NOCASE;",
        (table_name,),
    )
    match = cur.fetchone()
    if not match:
        print(f"[-] Error: Table '{table_name}' does not exist in sentinel.db.")
        return

    real_table = match[0]
    cur.execute(f"PRAGMA table_info(\"{real_table}\");")
    columns = [c[1] for c in cur.fetchall()]

    # Query rows
    cur.execute(f"SELECT * FROM \"{real_table}\" LIMIT {limit};")
    rows = cur.fetchall()

    print(f"\n[+] Showing up to {limit} records from table: '{real_table}' (Total: {len(rows)})")
    print(format_table(columns, rows, max_col_width=35))
    print()


def main():
    if not DB_PATH.exists():
        print(f"[-] Database not found at: {DB_PATH}")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    try:
        args = [a for a in sys.argv[1:] if not a.startswith("-")]
        if not args:
            show_summary(conn)
        else:
            show_table(conn, args[0])
    finally:
        conn.close()


if __name__ == "__main__":
    main()

