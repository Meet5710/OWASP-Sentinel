"""Subprocess Wrappers for External Security CLI Tools.

Provides sandboxed subprocess execution wrappers for external tools (sqlmap, XSStrike,
and pip-audit) without importing their source code directly or using shell=True.
"""

import json
import subprocess


def run_sqlmap_cli(target_url: str, sqlmap_path: str, timeout: int = 300) -> dict:
    """Execute sqlmap CLI tool against target URL via subprocess.

    Args:
        target_url: Assessment endpoint URL.
        sqlmap_path: File system path to sqlmap entrypoint script.
        timeout: Maximum execution seconds before timing out (default: 300s).

    Returns:
        Dict containing:
        - "stdout": Standard output text from sqlmap
        - "stderr": Standard error text from sqlmap
        - "exit_code": Process return code integer
    """
    cmd = [
        "python3",
        sqlmap_path,
        "-u",
        target_url,
        "--batch",
        "--level=1",
        "--risk=1",
        "--output-dir",
        "/tmp/sqlmap_out",
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        stdout = proc.stdout if isinstance(proc.stdout, str) else proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr if isinstance(proc.stderr, str) else proc.stderr.decode("utf-8", errors="replace")
        exit_code = proc.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout.decode("utf-8", errors="replace") if exc.stdout else "")
        stderr = "Command timed out."
        exit_code = -1

    return {
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
    }


def run_xsstrike_cli(target_url: str, xsstrike_path: str, timeout: int = 300) -> dict:
    """Execute XSStrike CLI tool against target URL via subprocess.

    Args:
        target_url: Assessment endpoint URL with parameters.
        xsstrike_path: File system path to xsstrike.py entrypoint script.
        timeout: Maximum execution seconds before timing out (default: 300s).

    Returns:
        Dict containing:
        - "stdout": Standard output text from XSStrike
        - "stderr": Standard error text from XSStrike
        - "exit_code": Process return code integer
        - "vulnerable": Boolean indicating whether "Vulnerable" marker appeared in stdout
    """
    cmd = [
        "python3",
        xsstrike_path,
        "-u",
        target_url,
        "--skip",
        "--skip-dom",
        "--console-log-level",
        "VULN",
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        stdout = proc.stdout if isinstance(proc.stdout, str) else proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr if isinstance(proc.stderr, str) else proc.stderr.decode("utf-8", errors="replace")
        exit_code = proc.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout.decode("utf-8", errors="replace") if exc.stdout else "")
        stderr = "Command timed out."
        exit_code = -1

    return {
        "stdout": stdout,
        "stderr": stderr,
        "exit_code": exit_code,
        "vulnerable": "Vulnerable" in stdout,
    }


def run_pip_audit(requirements_path: str, timeout: int = 300) -> dict:
    """Execute pip-audit CLI tool on requirements file and parse vulnerability findings.

    Args:
        requirements_path: Path to requirements.txt or dependencies file.
        timeout: Maximum execution seconds before timing out (default: 300s).

    Returns:
        Dict containing:
        - "vulnerabilities": List of parsed vulnerability dictionaries
    """
    cmd = [
        "pip-audit",
        "-r",
        requirements_path,
        "--format",
        "json",
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        stdout = proc.stdout if isinstance(proc.stdout, str) else (proc.stdout.decode("utf-8", errors="replace") if proc.stdout else "")
    except subprocess.TimeoutExpired:
        return {"vulnerabilities": []}
    except Exception:
        return {"vulnerabilities": []}

    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, TypeError):
        return {"vulnerabilities": []}

    if isinstance(data, dict):
        if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
            return {"vulnerabilities": data["vulnerabilities"]}
        if "dependencies" in data and isinstance(data["dependencies"], list):
            vulns = []
            for dep in data["dependencies"]:
                for v in dep.get("vulns", []):
                    vulns.append(
                        {
                            "package": dep.get("name"),
                            "version": dep.get("version"),
                            "id": v.get("id"),
                            "fix_versions": v.get("fix_versions", []),
                            "description": v.get("description", ""),
                        }
                    )
            return {"vulnerabilities": vulns}
    elif isinstance(data, list):
        return {"vulnerabilities": data}

    return {"vulnerabilities": []}

