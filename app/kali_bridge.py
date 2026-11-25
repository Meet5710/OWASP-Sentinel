import requests
import logging

logger = logging.getLogger("sentinel.kali_bridge")

# This points to the SSH tunnel on your Windows machine
KALI_API_URL = "http://127.0.0.1:5000"

TOOL_COMMANDS = {
    "nmap":     "nmap -sV -sC {extra} {target}",
    "nikto":    "nikto -h {target} {extra}",
    "gobuster": "gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt {extra}",
    "sqlmap":   "sqlmap -u {target} --batch --level=1 --risk=1 {extra}",
    "nuclei":   "nuclei -u {target} {extra}",
    "wpscan":   "wpscan --url {target} {extra}",
}

def build_kali_command(tool: str, target: str, extra_args: str = "") -> str:
    template = TOOL_COMMANDS.get(tool, f"{tool} {{extra}} {{target}}")
    return template.format(target=target, extra=extra_args).strip()

def run_tool_on_kali(command: str, timeout: int = 600) -> dict:
    """Execute a command via the Kali MCP server."""
    logger.info("Sending to Kali MCP: %s", command)
    try:
        response = requests.post(
            f"{KALI_API_URL}/api/command",
            json={"command": command},
            timeout=timeout
        )
        response.raise_for_status()
        data = response.json()
        
        # The MCP server returns output in different formats depending on the tool
        # We normalize it here to match what your UI expects
        output = data.get("output", "")
        if not output and "stdout" in data:
            output = data["stdout"]
            
        return {
            "stdout": output,
            "stderr": data.get("stderr", ""),
            "returncode": data.get("returncode", 0),
            "elapsed_seconds": data.get("elapsed_seconds", 0)
        }
    except Exception as e:
        logger.error(f"Kali bridge error: {e}")
        return {
            "stdout": "",
            "stderr": f"[!] Failed to connect to Kali MCP Server. Is the SSH tunnel running?\nError: {e}",
            "returncode": -1
        }