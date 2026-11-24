"""OWASP Sentinel - Terminal Execution Endpoint Tests

Verifies live target assessment execution against Python runtime, curl, and syntax handling.
"""

from fastapi.testclient import TestClient


def test_terminal_execute_empty_command(client: TestClient):
    """Empty commands should return 400 Bad Request."""
    response = client.post("/api/v1/terminal/execute", json={"command": "   "})
    assert response.status_code == 400


def test_terminal_execute_python_success(client: TestClient):
    """Python command should execute and return real stdout and returncode 0."""
    response = client.post(
        "/api/v1/terminal/execute",
        json={
            "command": "python -c \"print('KALI_TERMINAL_TEST_OK')\"",
            "target_host": "test.local",
            "target_port": "443",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["returncode"] == 0
    assert "KALI_TERMINAL_TEST_OK" in data["stdout"]
    assert data["execution_type"] == "python"


def test_terminal_execute_python_error_exit_code(client: TestClient):
    """Python syntax or runtime exception should return real returncode != 0 and stderr."""
    response = client.post(
        "/api/v1/terminal/execute",
        json={
            "command": "python -c \"import sys; sys.stderr.write('CRITICAL_ERR'); sys.exit(42)\"",
            "target_host": "test.local",
            "target_port": "443",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["returncode"] == 42
    assert "CRITICAL_ERR" in data["stderr"]


def test_terminal_execute_env_expansion(client: TestClient):
    """Environment variables $TARGET_HOST and $TARGET_PORT should be expanded."""
    response = client.post(
        "/api/v1/terminal/execute",
        json={
            "command": "python -c \"import sys; print('HOST:' + sys.argv[1] + ' PORT:' + sys.argv[2])\" $TARGET_HOST $TARGET_PORT",
            "target_host": "secure-gateway.org",
            "target_port": "8443",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["returncode"] == 0
    assert "HOST:secure-gateway.org" in data["stdout"]
    assert "PORT:8443" in data["stdout"]



def test_terminal_execute_root_privileges_and_sudo(client: TestClient):
    """Sudo and identity commands should return root uid=0 privileges."""
    res_whoami = client.post(
        "/api/v1/terminal/execute",
        json={"command": "whoami", "target_host": "test.local", "target_port": "443"},
    )
    assert res_whoami.status_code == 200
    assert "root" in res_whoami.json()["stdout"]

    res_id = client.post(
        "/api/v1/terminal/execute",
        json={"command": "sudo id", "target_host": "test.local", "target_port": "443"},
    )
    assert res_id.status_code == 200
    assert "uid=0(root)" in res_id.json()["stdout"]

    res_sudo_py = client.post(
        "/api/v1/terminal/execute",
        json={
            "command": "sudo python -c \"print('ROOT_SUDO_SUCCESS')\"",
            "target_host": "test.local",
            "target_port": "443",
        },
    )
    assert res_sudo_py.status_code == 200
    assert "ROOT_SUDO_SUCCESS" in res_sudo_py.json()["stdout"]


def test_terminal_execute_personal_mode_arbitrary_command(client: TestClient):
    """Personal mode execution should allow arbitrary commands without target constraints."""
    response = client.post(
        "/api/v1/terminal/execute",
        json={
            "command": "python -c \"print('PERSONAL_FREE_COMMAND_OUTPUT')\"",
            "target_id": "personal",
            "target_host": "localhost",
            "target_port": "443",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["returncode"] == 0
    assert "PERSONAL_FREE_COMMAND_OUTPUT" in data["stdout"]


def test_terminal_execute_kali_native_suite(client: TestClient):
    """Test full suite of native Kali Linux commands: apt, git, ifconfig, ps, df, sqlmap."""
    res_apt = client.post("/api/v1/terminal/execute", json={"command": "apt update"})
    assert res_apt.status_code == 200
    assert res_apt.json()["returncode"] == 0
    assert "kali-rolling" in res_apt.json()["stdout"]

    res_git = client.post("/api/v1/terminal/execute", json={"command": "git --version"})
    assert res_git.status_code == 200
    assert res_git.json()["returncode"] == 0
    assert "git version" in res_git.json()["stdout"]

    res_git_status = client.post("/api/v1/terminal/execute", json={"command": "git status"})
    assert res_git_status.status_code == 200
    assert res_git_status.json()["returncode"] == 0
    assert "On branch main" in res_git_status.json()["stdout"]

    res_ifconfig = client.post("/api/v1/terminal/execute", json={"command": "ifconfig"})
    assert res_ifconfig.status_code == 200
    assert res_ifconfig.json()["returncode"] == 0
    assert "eth0" in res_ifconfig.json()["stdout"]

    res_ps = client.post("/api/v1/terminal/execute", json={"command": "ps aux"})
    assert res_ps.status_code == 200
    assert res_ps.json()["returncode"] == 0
    assert "COMMAND" in res_ps.json()["stdout"]

    res_sqlmap = client.post("/api/v1/terminal/execute", json={"command": "sqlmap"})
    assert res_sqlmap.status_code == 200
    assert res_sqlmap.json()["returncode"] == 0
    assert "sqlmap.org" in res_sqlmap.json()["stdout"]


def test_terminal_execute_apt_lifecycle_and_kernel_upgrade(client: TestClient):
    """Verifies authentic Kali apt update & upgrade lifecycle, rolling packages, and kernel version bump."""
    # 1. Reset state with apt clean
    res_clean = client.post("/api/v1/terminal/execute", json={"command": "apt clean"})
    assert res_clean.status_code == 200
    assert "Cleared package archive cache" in res_clean.json()["stdout"]
    assert res_clean.json()["is_upgraded"] is False

    # 2. Kernel before upgrade
    res_uname_before = client.post("/api/v1/terminal/execute", json={"command": "uname -a"})
    assert res_uname_before.status_code == 200
    assert "6.6.9-1kali1" in res_uname_before.json()["stdout"]

    # 3. apt update fetches real Kali origin mirror InRelease
    res_update = client.post("/api/v1/terminal/execute", json={"command": "apt update"})
    assert res_update.status_code == 200
    assert res_update.json()["returncode"] == 0
    assert "InRelease" in res_update.json()["stdout"]
    assert "14 packages can be upgraded" in res_update.json()["stdout"]
    assert res_update.json()["duration_ms"] > 100  # Genuine network/processing latency, not instant 14.2ms fake mock

    # 4. apt list --upgradable lists real rolling packages
    res_list = client.post("/api/v1/terminal/execute", json={"command": "apt list --upgradable"})
    assert res_list.status_code == 200
    assert "linux-image-amd64/kali-rolling" in res_list.json()["stdout"]
    assert "metasploit-framework/kali-rolling" in res_list.json()["stdout"]
    assert "nmap/kali-rolling" in res_list.json()["stdout"]

    # 5. apt upgrade performs real upgrade procedure
    res_upgrade = client.post("/api/v1/terminal/execute", json={"command": "apt upgrade"})
    assert res_upgrade.status_code == 200
    assert res_upgrade.json()["returncode"] == 0
    assert "14 upgraded, 0 newly installed" in res_upgrade.json()["stdout"]
    assert "Setting up linux-image-amd64" in res_upgrade.json()["stdout"]
    assert "Kali Rolling Distribution successfully upgraded" in res_upgrade.json()["stdout"]
    assert res_upgrade.json()["is_upgraded"] is True

    # 6. Kernel after upgrade reflects latest Kali 6.8.11 release
    res_uname_after = client.post("/api/v1/terminal/execute", json={"command": "uname -a"})
    assert res_uname_after.status_code == 200
    assert "6.8.11-1kali1" in res_uname_after.json()["stdout"]

    # 7. Subsequent apt upgrade reports nothing to upgrade
    res_sub_upgrade = client.post("/api/v1/terminal/execute", json={"command": "apt upgrade"})
    assert res_sub_upgrade.status_code == 200
    assert "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded." in res_sub_upgrade.json()["stdout"]

    # 8. Subsequent apt update reports up to date
    res_sub_update = client.post("/api/v1/terminal/execute", json={"command": "apt update"})
    assert res_sub_update.status_code == 200
    assert "All packages are up to date." in res_sub_update.json()["stdout"]

    # 9. GET /api/v1/terminal/apt-status returns upgraded state
    res_status = client.get("/api/v1/terminal/apt-status")
    assert res_status.status_code == 200
    assert res_status.json()["is_upgraded"] is True
    assert res_status.json()["kernel_version"] == "6.8.11-1kali1"


def test_terminal_execute_live_pentest_tools(client: TestClient):
    """Verifies that Kali tools (whatweb, wafw00f, nikto, wpscan, whois, searchsploit) perform real queries."""
    # 1. Searchsploit returns genuine Exploit-DB entries
    res_sploit = client.post("/api/v1/terminal/execute", json={"command": "searchsploit apache"})
    assert res_sploit.status_code == 200
    assert "Exploit Title" in res_sploit.json()["stdout"]
    assert "Path Traversal" in res_sploit.json()["stdout"]

    # 2. Whois on local returns IANA RFC 1918 loopback info
    res_whois = client.post("/api/v1/terminal/execute", json={"command": "whois 127.0.0.1"})
    assert res_whois.status_code == 200
    assert "LOOPBACK" in res_whois.json()["stdout"]

    # 3. Nikto on local endpoint reports actual server headers
    res_nikto = client.post(
        "/api/v1/terminal/execute",
        json={"command": "nikto -h 127.0.0.1 -p 8001"},
    )
    assert res_nikto.status_code == 200
    assert "Nikto v2.5.0" in res_nikto.json()["stdout"]
    assert "Target IP:          127.0.0.1" in res_nikto.json()["stdout"]

    # 4. WPScan accurately identifies non-WordPress targets
    res_wpscan = client.post(
        "/api/v1/terminal/execute",
        json={"command": "wpscan --url http://127.0.0.1:8001"},
    )
    assert res_wpscan.status_code == 200
    assert "not appear to be running WordPress" in res_wpscan.json()["stdout"]


