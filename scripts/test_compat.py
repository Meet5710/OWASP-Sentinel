import re
from pathlib import Path

def modernize_python_code(code: str) -> str:
    code = code.expandtabs(4)
    code = re.sub(r'\bimport\s+urllib2\b', 'import urllib.request as urllib2', code)
    code = re.sub(r'\bfrom\s+urllib2\s+import\b', 'from urllib.request import', code)
    code = re.sub(r'\bimport\s+httplib\b', 'import http.client as httplib', code)
    code = re.sub(r'\bfrom\s+httplib\s+import\b', 'from http.client import', code)
    code = re.sub(r'\bimport\s+commands\b', 'import subprocess as commands', code)
    code = re.sub(r'\bimport\s+StringIO\b', 'import io as StringIO', code)
    code = re.sub(r'\bfrom\s+StringIO\s+import\s+StringIO\b', 'from io import StringIO', code)
    code = re.sub(r'except\s+([a-zA-Z0-9_\.]+)\s*,\s*([a-zA-Z0-9_]+)\s*:', r'except \1 as \2:', code)

    lines = code.splitlines()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        indent = line[:len(line) - len(line.lstrip())]
        if stripped.startswith("print ") and not stripped.startswith("print("):
            content = stripped[6:].strip()
            if content.endswith(","):
                new_lines.append(f"{indent}print({content[:-1].strip()}, end=' ')")
            else:
                new_lines.append(f"{indent}print({content})")
        elif stripped == "print":
            new_lines.append(f"{indent}print()")
        else:
            new_lines.append(line)

    return "\n".join(new_lines)

scripts_dir = Path("Practice_Scripts")
all_py = list(scripts_dir.glob("*.py"))
print(f"Total scripts found: {len(all_py)}")

success = 0
failed = 0
for p in all_py:
    code = p.read_text(encoding="utf-8", errors="ignore")
    mod_code = modernize_python_code(code)
    try:
        compile(mod_code, str(p), "exec")
        success += 1
    except Exception as e:
        failed += 1

print(f"Compilation Results: {success} succeeded, {failed} failed.")
