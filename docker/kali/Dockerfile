# ==============================================================================
# OWASP Sentinel - Unified Kali Linux MCP & Pentesting Container
# ==============================================================================
# Base Repo #1: https://github.com/zebbern/zebbern-kali-mcp
# Additional GitHub repos / tools are merged cleanly in layered sections below.

FROM ghcr.io/zebbern/zebbern-kali-mcp:latest

ENV DEBIAN_FRONTEND=noninteractive

# ------------------------------------------------------------------------------
# Repo #2 Additions: https://github.com/k3nn3dy-ai/kali-mcp
# Unique tools not present in Repo #1 (skipping duplicates like nmap, sqlmap,
# nikto, gobuster, dirb, hydra, amass, subfinder, httpx, waybackurls, metasploit)
# ------------------------------------------------------------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    whois \
    testssl.sh \
    gospider \
    nfs-common \
    hashid \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------------------------
# Full 72/72 Arsenal Completion: Network, Web, Auth, RE, Cloud, Forensics, OSINT
# ------------------------------------------------------------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    rustscan \
    autorecon \
    dnsenum \
    theharvester \
    enum4linux-ng \
    feroxbuster \
    dirsearch \
    whatweb \
    wafw00f \
    medusa \
    patator \
    smbmap \
    ghidra \
    sleuthkit \
    autopsy \
    spiderfoot \
    sherlock \
    trivy \
    python3-shodan \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Go-based OSINT/Bug Bounty & Exploitation tools + symlink existing Go/pipx binaries into /usr/local/bin
RUN go install github.com/haccer/subjack@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/jaeles-project/jaeles@latest && \
    go install github.com/hahwul/dalfox/v2@latest && \
    go clean -cache -modcache && \
    for b in /root/go/bin/* /root/.local/bin/*; do \
        [ -e "$b" ] && ln -sf "$b" "/usr/local/bin/$(basename "$b")"; \
    done

# Top Exploitation Tools (commix, wpscan, whatweb via apt; nosqlmap via GitHub since it is not in kali-rolling apt)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    commix \
    wpscan \
    whatweb \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* && \
    git clone --depth 1 https://github.com/codingo/NoSQLMap.git /opt/nosqlmap && \
    printf '#!/bin/sh\nexec python3 /opt/nosqlmap/nosqlmap.py "$@"\n' > /usr/local/bin/nosqlmap && \
    chmod +x /usr/local/bin/nosqlmap

# Cloud, Container & Censys tools installed cleanly into isolated Python 3.12 envs via uv
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh && \
    UV_TOOL_BIN_DIR=/usr/local/bin uv tool install --python 3.12 prowler && \
    UV_TOOL_BIN_DIR=/usr/local/bin uv tool install --python 3.12 scoutsuite && \
    UV_TOOL_BIN_DIR=/usr/local/bin uv tool install --python 3.12 checkov && \
    UV_TOOL_BIN_DIR=/usr/local/bin uv tool install --python 3.12 kube-hunter && \
    UV_TOOL_BIN_DIR=/usr/local/bin uv tool install --python 3.12 censys && \
    uv cache clean

# kube-bench & docker-bench-security
RUN curl -fsSL -o /tmp/kube-bench.deb \
        https://github.com/aquasecurity/kube-bench/releases/download/v0.16.0/kube-bench_0.16.0_linux_amd64.deb && \
    dpkg -i /tmp/kube-bench.deb && \
    rm -f /tmp/kube-bench.deb && \
    git clone --depth 1 https://github.com/docker/docker-bench-security.git /opt/docker-bench-security && \
    chmod +x /opt/docker-bench-security/docker-bench-security.sh && \
    ln -sf /opt/docker-bench-security/docker-bench-security.sh /usr/local/bin/docker-bench-security

# Compatibility symlinks + Python 3.14 configparser fix for jwt_tool
RUN ln -sf /usr/bin/testssl /usr/local/bin/testssl.sh && \
    ln -sf /usr/bin/nxc /usr/local/bin/crackmapexec && \
    ln -sf /usr/share/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless && \
    ln -sf /usr/share/dnsenum/dns.txt /usr/share/wordlists/dnsmap.txt && \
    python3 -c "p='/usr/local/bin/jwt_tool'; s=open(p).read().replace('allow_no_value=True', 'allow_no_value=True, delimiters=(\"=\",)'); s=s.replace(\"set this value to:\", \"set this value to\"); open(p,'w').write(s)" && \
    rm -rf /root/.jwt_tool

# Ensure standard Go & pipx tool directories are always on PATH
ENV PATH="/usr/local/bin:/root/go/bin:/root/.local/bin:${PATH}"
