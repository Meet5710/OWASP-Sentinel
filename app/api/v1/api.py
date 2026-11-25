"""OWASP Sentinel - API v1 Router Aggregator

Combines all v1 API modules (Health, Targets, Scans, Intelligence).
"""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    assets,
    audit,
    findings,
    health,
    history,
    kali,
    rules,
    scans,
    schedules,
    scopes,
    targets,
    taxonomy,
    terminal,
    tunnel,
    sql,
    path_finder,
    xssspect,
)

api_router = APIRouter()

api_router.include_router(health.router, tags=["Health"])
api_router.include_router(tunnel.router, prefix="/tunnel", tags=["Ngrok Public Tunnel"])
api_router.include_router(terminal.router, prefix="/terminal", tags=["Kali Terminal"])
api_router.include_router(targets.router, prefix="/targets", tags=["Target Validation"])
api_router.include_router(scopes.router, prefix="/scopes", tags=["Scope Grants"])
api_router.include_router(assets.router, prefix="/assets", tags=["Asset Inventory & Authorization"])
api_router.include_router(scans.router, prefix="/scans", tags=["Assessments & Scans"])
api_router.include_router(path_finder.router, prefix="/path-finder", tags=["Path Finder (Authorized Endpoint Discovery)"])
api_router.include_router(path_finder.router, prefix="/pathfinder", tags=["Path Finder (Authorized Endpoint Discovery)"])
api_router.include_router(xssspect.router, prefix="/xssspect", tags=["XSSpect (Reflected XSS Scanner)"])
api_router.include_router(schedules.router, prefix="/schedules", tags=["Assessment Scheduling"])
api_router.include_router(findings.router, prefix="/findings", tags=["Finding Management & OWASP Mappings"])
api_router.include_router(history.router, prefix="/history", tags=["Posture History & Patch Verification"])
api_router.include_router(rules.router, prefix="/rules", tags=["Detection Rules & OWASP Coverage"])
api_router.include_router(taxonomy.router, prefix="/taxonomy", tags=["OWASP Intelligence & Taxonomy"])
api_router.include_router(audit.router, prefix="/audit", tags=["Audit Log"])
api_router.include_router(kali.router, prefix="/kali", tags=["Kali Pentester"])
api_router.include_router(sql.router, prefix="/sql", tags=["SQL Target Discovery & Dork Engine"])
