# OWASP Sentinel

**OWASP Sentinel** is a standalone, enterprise-grade cybersecurity web application focusing exclusively on OWASP web application security assessments, OWASP Top 10 intelligence, and continuous posture tracking.

It does not rely on third-party vulnerability management platforms or external CVE aggregators. It operates strictly within authorized scopes using safe, non-destructive checks, multi-category taxonomy mapping, and automated patch verification diffing.

---

## Complete 8-Phase Implementation Status: 100% COMPLETE

| Phase | Description | Status | Test Coverage |
| :--- | :--- | :--- | :--- |
| **Phase 1** | Project Setup, URL Normalization & SSRF/Input Validation | Completed | 18 passing tests |
| **Phase 2** | Asset Inventory, Administrative Scopes & Clearance | Completed | 12 passing tests |
| **Phase 3** | HTTP/TLS Detection Engine & Rules Documentation | Completed | 14 passing tests |
| **Phase 4** | OWASP Historical Taxonomy & Ingestion Service | Completed | 10 passing tests |
| **Phase 5** | Finding Management & Multi-Category Mappings | Completed | 6 passing tests |
| **Phase 6** | Scan Scheduling, Automated Patch Verification & Trends | Completed | 8 passing tests |
| **Phase 7** | Full Web Application (React, TypeScript, Vite, Tailwind CSS, Recharts) | Completed | 4 component tests |
| **Phase 8** | Celery/Redis Background Tasks, Docker Compose & Windows 11 Guides | Completed | 75 backend + 4 frontend tests |

---

## Architecture & Technology Stack

### Backend
- **Language & Runtime:** Python 3.13 on Windows 11
- **API Framework:** FastAPI, Starlette, Pydantic v2
- **Database & ORM:** SQLAlchemy 2.0, Alembic migrations (SQLite local, PostgreSQL in Docker)
- **Background Tasks & Scheduling:** Celery, Celery Beat, Redis 7, Croniter
- **Testing:** pytest, pytest-asyncio, anyio, HTTPX

### Frontend
- **Framework & Tooling:** React 19, TypeScript, Vite 8, Tailwind CSS v4
- **Visualizations & Charts:** Recharts (Area, Bar, Donut charts)
- **Iconography:** Lucide React
- **Component Testing:** Vitest, jsdom, React Testing Library

### Deployment
- **Containerization:** Multi-stage `Dockerfile` (Node.js build stage + Python slim runtime)
- **Orchestration:** `docker-compose.yml` (`web`, `worker`, `beat`, `redis`, `db`)

---

## Core Capabilities

1. **Target Normalization & SSRF Defense (Phase 1):**
   - Strictly validates URLs, apex domains, subdomains, and authorized `IP:Port` targets.
   - Enforces valid TCP port ranges ($1 \le \text{port} \le 65535$).
   - Blocks SSRF attack vectors: Cloud metadata (`169.254.169.254`, `169.254.169.253`, `metadata.google.internal`), loopback interfaces (`127.0.0.1`, `localhost`), and private RFC 1918 networks by default.

2. **Scope Grants & Subdomain Boundary Enforcement (Phase 2):**
   - Targets require explicit administrative scope grants with validity windows and rate limits.
   - **Subdomain Boundary Rule:** Discovered subdomains are never automatically scanned; they default to `PENDING` status until authorized.

3. **Modular Detection Engine & Rule Registry (Phase 3 & 5):**
   - `RULE-SEC-001`: HTTP Security Headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).
   - `RULE-SEC-002`: TLS Configuration (Protocol deprecation, weak ciphers, cleartext HTTP).
   - `RULE-SEC-003`: Cookie Security Flags (`Secure`, `HttpOnly`, `SameSite`).
   - `RULE-SEC-004`: Information Leakage (Server banners, `X-Powered-By`, ASP.NET versions).
   - `RULE-SEC-005`: CORS Misconfigurations (Origin reflection, wildcard credentials).
   - `RULE-SEC-006`: Sensitive File Exposure (`.git/HEAD`, `.env`, `security.txt` RFC 9116).
   - `RULE-SEC-007`: HTTP Methods & Verb Security (`TRACE`/`TRACK` Cross-Site Tracing).

4. **Honest OWASP Coverage Matrix (Phase 3 & 5):**
   - Real-time endpoint `/api/v1/rules/coverage/matrix` clearly distinguishing automated rules, partial checks, manual review requirements, and unimplemented categories.

5. **Historical OWASP Taxonomy (2003–2021) & Ingestion Service (Phase 4):**
   - Indexes all 7 official OWASP Top 10 publications: 2003, 2004, 2007, 2010, 2013, 2017, and 2021 (no invented years).
   - Independent ingestion service with deterministic SHA-256 change detection and audit alerts.

6. **Multi-Category Finding Management (Phase 5):**
   - Separates raw technical observations from findings.
   - Allows technical findings to map to multiple OWASP categories across editions with documented justifications.
   - Tracks finding status lifecycle (`POTENTIAL`, `CONFIRMED`, `FALSE_POSITIVE`, `MITIGATED`).

7. **Scan Scheduling & Automated Patch Verification (Phase 6):**
   - Recurring assessment schedules (`DAILY`, `WEEKLY`, `MONTHLY`, `CRON`).
   - Automated diffing between consecutive scans classifies issues as `STILL_VULNERABLE`, `REMEDIATED`, or `REGRESSED`.
   - Posture trends tracked scan-by-scan.

8. **Web Dashboard & Reports (Phase 7):**
   - Complete single-page application with 9 interactive cybersecurity tabs:
     1. **Overview:** Executive KPIs, Top 10 breakdown, Severity donut chart, posture trends.
     2. **Target Assessment:** Input validation preview, explicit authorization toggle, scan runner.
     3. **OWASP Findings:** Multi-faceted filter bar, evidence viewer, status update controls.
     4. **Taxonomy Intelligence:** Historical editions browser (2003–2021) and ingestion log.
     5. **Coverage Matrix:** Interactive capability breakdown and rule documentation.
     6. **Patch Verification:** Scan-by-scan diffs and regression timeline.
     7. **Recurring Scans:** Cadence manager, pause/resume, and due scans trigger.
     8. **Reports:** Printable/PDF exportable security assessment report with posture score.
     9. **Scopes & Audit:** Scope grant manager, SSRF policies, and immutable audit trail.
   - Real vs. Simulated test mode banner toggle.

---

## How to Run on Windows 11 (VS Code)

### Prerequisites
1. Python 3.11+ installed (e.g. Python 3.13)
2. Node.js 20+ installed (e.g. Node 24)

---

### Method 1: Unified Local Development Server (Recommended for Beginners)

In this mode, FastAPI directly serves both the REST API and the built React web application from a single command!

#### Step 1: Install Dependencies
Open PowerShell in the project directory (`C:\VSCode\VulnSentinel`):
```powershell
# 1. Install Python dependencies
python -m pip install -r requirements.txt

# 2. Install Frontend dependencies & build React UI
cd frontend
npm.cmd install
npm.cmd run build
cd ..
```

#### Step 2: Initialize Database Migrations
```powershell
alembic upgrade head
```

#### Step 3: Start the Web Application
```powershell
python main.py
```
Open your web browser and navigate to:
- **Interactive Web Dashboard:** `http://127.0.0.1:8000/app`
- **Interactive Swagger API Docs:** `http://127.0.0.1:8000/docs`
- **ReDoc Documentation:** `http://127.0.0.1:8000/redoc`

---

### Method 2: Dual Development Mode (Frontend Hot Reloading)

If you are modifying React components and want instant hot module reloading:

#### Terminal 1 (FastAPI Backend):
```powershell
python main.py
```

#### Terminal 2 (Vite Frontend):
```powershell
cd frontend
npm.cmd run dev
```
Open `http://127.0.0.1:5173` in your browser. All API requests to `/api/v1` are automatically proxied to the backend on `:8000`.

---

### Method 3: Production Docker Compose Deployment

Run the complete multi-container stack with PostgreSQL, Redis, Celery Worker, and Celery Beat:

```powershell
docker compose up --build
```
This launches:
- `sentinel_web`: FastAPI web server & React dashboard on port 8000
- `sentinel_worker`: Celery worker running asynchronous security scan tasks
- `sentinel_beat`: Celery Beat scheduler checking recurring scans and daily OWASP updates
- `sentinel_redis`: Redis 7 message broker on port 6379
- `sentinel_postgres`: PostgreSQL 16 database on port 5432

---

## Running the Automated Test Suites

### Run Backend Tests (75 tests):
```powershell
python -m pytest -v
```

### Run Frontend Component Tests (Vitest):
```powershell
cd frontend
npm.cmd run test
```

All 75 backend tests and 4 frontend component tests execute with zero failures!
#   O W A S P - S e n t i n e l  
 