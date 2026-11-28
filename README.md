# OWASP Sentinel (`VulnSentinel`)

**OWASP Sentinel** is a full-stack cybersecurity assessment, reconnaissance, and OWASP Top 10 intelligence platform. It combines an async Python/FastAPI assessment engine, a **React 19 + TypeScript + Vite 8** dashboard, and an integrated **75-tool Kali Linux Docker container (`sentinel_kali`)** with strict scope authorization and SSRF protections.

---

## Architecture & Technology Stack

### Backend
- **Language & Runtime:** Python 3.13
- **API Framework:** FastAPI, Starlette, Uvicorn (ASGI), Pydantic v2
- **Database & ORM:** SQLAlchemy 2.1, Alembic migrations (SQLite for local dev, PostgreSQL 16 in Docker)
- **HTTP & Parsing:** HTTPX (async probing/crawling), Requests (Kali container bridge), BeautifulSoup4
- **Background Tasks & Scheduling:** Celery 5, Celery Beat, Redis 7, Croniter
- **Testing:** `pytest`, `anyio`

### Frontend
- **Framework & Tooling:** React 19, TypeScript, Vite 8, Tailwind CSS v4
- **UI & Visualization:** `react-select`, `lucide-react`, `recharts`, `framer-motion`, `jspdf`, `html2pdf.js`
- **Dev Proxy:** Vite on `:5173` proxies `/api/*` requests to FastAPI on `http://127.0.0.1:8001`
- **Testing & Linting:** Vitest, Testing Library (`jsdom`), `oxlint`

### Docker & Kali Execution Container
- **App Image (`Dockerfile`):** Multi-stage build (Node 22 frontend build + Python 3.13 runtime on port `8000`)
- **Kali Image (`docker/kali/Dockerfile`):** Unified Kali Linux container (`sentinel_kali`) built on `ghcr.io/zebbern/zebbern-kali-mcp:latest` + SecLists/dirb wordlists + 75 installed pentesting tools (`nmap`, `rustscan`, `masscan`, `autorecon`, `gobuster`, `feroxbuster`, `ffuf`, `dirsearch`, `nuclei`, `nikto`, `sqlmap`, `wpscan`, `dalfox`, `commix`, `nosqlmap`, `jaeles`, `whatweb`, `wafw00f`, `arjun`, `httpx`, `katana`, `gospider`, `testssl.sh`, `hydra`, `john`, `hashcat`, `ghidra`, `trivy`, `prowler`, `exiftool`, `subfinder`, `amass`, etc.)
- **Compose Stack (`docker-compose.yml`):** `web` (`:8000`), `worker`, `beat`, `kali` (`127.0.0.1:5001->5000`, `127.0.0.1:1080->1080`), `redis` (`:6379`), `db` (`:5432`)

---

## Core Capabilities

1. **Target Validation, Scope Control & SSRF Defense**
   - Normalizes and validates URLs, apex domains, subdomains, and `IP:Port` targets within valid TCP port ranges (`1–65535`).
   - Blocks SSRF vectors (cloud metadata endpoints `169.254.169.254`, loopback, and private RFC 1918 ranges unless explicitly authorized).
   - Enforces administrative `ScopeGrant` and `AuthorizedAsset` approval before active assessment.

2. **Subdomain Finder (`Subdomain Finder`)**
   - Multi-engine passive Certificate Transparency (`crt.sh`, CertSpotter), passive DNS (HackerTarget, AlienVault, Anubis), authoritative DNS/DoH record mining (`TXT`/`SPF`, `MX`, `NS`, `CNAME`), live header/HTML scraping, permutation probing, and wildcard DNS suppression.

3. **Path Finder (`Path Finder`)**
   - Supports **Quick**, **Recursive**, and **Exhaustive** discovery modes (`1,485+` to `6,072+` candidate paths).
   - Discovers routes from `robots.txt`, nested sitemaps (`sitemap.xml`, `sitemap_index.xml`, `wp-sitemap.xml`), intra-host `<script src>` SPA/JS bundles, and live HTML link crawling.
   - Filters false positives using baseline 404 hashing, Soft-404 fingerprinting, and wildcard redirect checks.

4. **Kali Pentester Arsenal (`Kali Pentester` — 75 Tools / 7 Categories)**
   - Executes real Kali Linux CLI tools inside `sentinel_kali` with searchable category filtering, **Installed only** filtering, live terminal output badges (`lines` and `findings` counts), and execution history.
   - **Nmap Two-Part Syntax:** Defaults to `-p- -sV -sC -A -T4 -Pn --script vuln`, with a **`Deep scan (vulners)`** checkbox after `Installed only` that fills Extra Arguments with `-sV --script vulners --script-args mincvss=7.0`.
   - **URL-to-File Fetching:** Automatically downloads `http(s)://` targets to `/tmp/sentinel_target_asset` for file-based forensics/RE tools (`exiftool`, `strings`, `binwalk`, `foremost`, `steghide`).
   - **Remote Bridge (Render + Ngrok):** Non-localhost deployments (e.g. `owasp-sentinel.onrender.com`) can connect to your local FastAPI backend & Kali container via an Ngrok URL saved in `localStorage`.

5. **OWASP Scanner Engine (`19` Detection Rules) & Taxonomy Intelligence**
   - Registers 19 built-in rules (`RULE-SEC-001` through `RULE-SEC-019`) covering HTTP Security Headers, TLS/crypto checks, Cookie flags, Info Leakage, CORS, Sensitive Files, HTTP Methods, Injection, Auth Failures, SSRF, XXE, CSRF, Redirects, DoS Resilience, Vulnerable Components, Data Integrity, Insecure Design, and Logging/Monitoring.
   - Maps findings across official OWASP Top 10 editions (**2003–2025**), computes the live **Coverage Matrix**, tracks **Proof of Concept**, **Recurring Scans**, **Patch Verification**, PDF export reports, and an immutable **Audit Trail**.

---

## Dashboard Navigation (11 Tabs)

| Section | Tab | Purpose |
| :--- | :--- | :--- |
| **CORE POSTURE** | **Overview** | Executive KPIs, severity breakdown, Top 10 distribution, posture trends |
| **CORE POSTURE** | **Target Assessment** | Target input validation, authorization clearance, OWASP rule scan runner |
| **CORE POSTURE** | **Subdomain Finder** | Multi-source passive/active subdomain enumeration & live HTTP checks |
| **CORE POSTURE** | **Path Finder** | Quick / Recursive / Exhaustive directory, sitemap, JS bundle & HTML route discovery |
| **CORE POSTURE** | **Kali Pentester** | 75 Kali Linux tools across 7 categories with line/finding counters & Ngrok bridge |
| **CORE POSTURE** | **OWASP Findings** | Search/filter findings, inspect evidence, manage lifecycle status |
| **TAXONOMY & COVERAGE** | **Taxonomy Intelligence** | Browse official OWASP Top 10 editions (2003–2025) & ingestion history |
| **TAXONOMY & COVERAGE** | **Coverage Matrix** | Automated vs. partial vs. manual rule coverage per OWASP category |
| **OPERATIONS & AUDIT** | **Recurring Scans** | Cron-based scan schedules (`DAILY`, `WEEKLY`, `MONTHLY`, `CRON`) |
| **OPERATIONS & AUDIT** | **Proof of Concept** | Finding PoC verification, patch diffing, and PDF report export |
| **OPERATIONS & AUDIT** | **Scopes & Audit** | Scope grants, Ngrok tunnel management, and audit log viewer |

---

## How to Run (Windows 11 / Local Dev)

### Prerequisites
- Python 3.11+ (tested on Python 3.13)
- Node.js 20+
- Docker Desktop (required for the `sentinel_kali` 75-tool container)

### 1. Start the Kali Docker Container
```powershell
docker compose build kali
docker compose up -d kali
```
Verify it is healthy at `http://127.0.0.1:5001/live`.

### 2. Install Backend & Frontend Dependencies
```powershell
python -m pip install -r requirements.txt

cd frontend
npm.cmd install
cd ..
```

### 3. Run in Dual Development Mode (Recommended for Development)
- **Terminal 1 — FastAPI Backend (`:8001`):**
  ```powershell
  python -m uvicorn app.main:app --host 127.0.0.1 --port 8001 --reload
  ```
- **Terminal 2 — Vite React UI (`:5173`):**
  ```powershell
  cd frontend
  npm.cmd run dev
  ```
Open:
- **React Web Dashboard:** `http://localhost:5173/`
- **FastAPI Swagger Docs:** `http://127.0.0.1:8001/docs`
- **ReDoc:** `http://127.0.0.1:8001/redoc`

### 4. Unified Production Build (`:8000`) or Full Docker Compose Stack
```powershell
# Build frontend and serve everything via FastAPI (app/main.py)
cd frontend
npm.cmd run build
cd ..
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# OR run the full 6-service Docker stack (web, worker, beat, kali, redis, db)
docker compose up -d --build
```

---

## Verification Commands

```powershell
# Path Finder & route safeguards pytest suite
python -m pytest tests/test_route_checker.py tests/test_path_finder_safeguards.py -v

# Frontend TypeScript check & production Vite build
cmd /c "cd frontend && npx tsc -b && npm run build"

# Frontend Vitest suite
cd frontend
npm.cmd run test
```
