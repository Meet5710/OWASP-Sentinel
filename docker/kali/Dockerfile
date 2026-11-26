# ==============================================================================
# OWASP Sentinel - Unified Kali Linux MCP & Pentesting Container
# ==============================================================================
# Base Repo #1: https://github.com/zebbern/zebbern-kali-mcp
# Additional GitHub repos / tools can be merged cleanly in layered sections below.

FROM ghcr.io/zebbern/zebbern-kali-mcp:latest

# ------------------------------------------------------------------------------
# Merged Repo Additions (add subsequent repos/tools below this line)
# ------------------------------------------------------------------------------

# Ensure standard Go & pipx tool directories are always on PATH
ENV PATH="/root/go/bin:/root/.local/bin:${PATH}"

