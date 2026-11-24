"""FastAPI Execution Backend for UI Security Scanning.

Provides HTTP REST endpoints for the frontend interface to check server status
and trigger authorized security assessment scans via the scanner orchestrator.
"""

from typing import Any
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

from scanner_main import scan


class ScanRequest(BaseModel):
    """Payload model for initiating a security scan."""

    target_url: str = Field(..., description="Target URL to be scanned")
    selected_checks: list[str] = Field(
        ...,
        description="List of OWASP category IDs to execute (e.g. ['A01', 'A02'])",
    )


app = FastAPI(
    title="OWASP Security Scanner API Backend",
    description="Execution backend bridging the UI to local security assessment routines.",
    version="1.0.0",
)

# Configure CORS middleware to accept requests from localhost and 127.0.0.1 on any port
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "http://127.0.0.1",
    ],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:[0-9]+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/status")
def get_status() -> dict[str, str]:
    """Check the operational health and readiness of the scanning backend.

    Returns:
        Dictionary indicating service status {"status": "online"}.
    """
    return {"status": "online"}


@app.post("/api/scan")
def run_scan(request: ScanRequest) -> dict[str, Any]:
    """Execute assessment checks against the target URL via the orchestrator.

    Args:
        request: Validated ScanRequest containing target_url and selected_checks.

    Returns:
        Dictionary containing target details, findings list, and summary metrics.
    """
    results = scan(
        target_url=request.target_url,
        selected_ids=request.selected_checks,
        auth={},
    )
    return results


if __name__ == "__main__":
    uvicorn.run("api_server:app", host="127.0.0.1", port=8000, reload=True)

