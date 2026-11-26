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

# Ensure standard Go & pipx tool directories are always on PATH
ENV PATH="/root/go/bin:/root/.local/bin:${PATH}"
