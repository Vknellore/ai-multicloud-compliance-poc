"""
AI-Powered Secure Multi-Cloud Compliance Platform — Proof of Concept
--------------------------------------------------------------------
Lightweight control plane demonstrating:
  - Multi-cloud + SAP findings aggregation
  - Policy / framework mapping
  - AI-style risk prioritization & remediation guidance
  - Unified dashboard + REST API
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = ROOT / "data" / "findings.json"
TEMPLATES_DIR = ROOT / "templates"
STATIC_DIR = ROOT / "static"

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="AI Multi-Cloud Compliance PoC",
    description="Proof of Concept control plane for AWS · Azure · SAP",
    version="0.1.0",
)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
Cloud = Literal["aws", "azure", "sap"]


class Finding(BaseModel):
    id: str
    cloud: Cloud
    resource: str
    type: str
    region: str
    control: str
    framework: str
    severity: Severity
    title: str
    description: str
    status: str
    remediation: str
    iac_snippet: str | None = None
    # AI-enriched fields (populated at runtime)
    risk_score: float = 0.0
    ai_priority: str = ""
    ai_explanation: str = ""
    business_impact: str = ""


class RemediateRequest(BaseModel):
    finding_id: str
    approved_by: str = Field(default="poc-operator")


class DashboardStats(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_cloud: dict[str, int]
    critical_open: int
    compliance_score: float
    last_refresh: str


# ---------------------------------------------------------------------------
# In-memory store (loaded once at startup)
# ---------------------------------------------------------------------------
FINDINGS: list[Finding] = []
REMEDIATION_LOG: list[dict[str, Any]] = []


def load_findings() -> list[Finding]:
    raw = json.loads(DATA_FILE.read_text())
    items: list[Finding] = []
    for cloud, rows in raw.items():
        for row in rows:
            items.append(Finding(cloud=cloud, **row))  # type: ignore[arg-type]
    return items


# ---------------------------------------------------------------------------
# AI-style Risk Engine (rule-based + heuristic — stands in for LLM)
# ---------------------------------------------------------------------------
SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 12, "LOW": 5, "INFO": 1}
CLOUD_CRITICALITY = {"sap": 1.25, "aws": 1.1, "azure": 1.1}  # SAP slightly higher
PUBLIC_EXPOSURE_KEYWORDS = ("public", "0.0.0.0/0", "allusers", "anonymous", "*")


def compute_risk_score(f: Finding) -> float:
    base = SEVERITY_WEIGHT.get(f.severity, 5)
    multiplier = CLOUD_CRITICALITY.get(f.cloud, 1.0)
    text = (f.title + " " + f.description).lower()
    if any(k in text for k in PUBLIC_EXPOSURE_KEYWORDS):
        multiplier *= 1.35
    if "encrypt" in text or "password" in text or "authoriz" in text:
        multiplier *= 1.15
    if f.cloud == "sap" and "s_tcode" in text:
        multiplier *= 1.3
    return round(min(base * multiplier, 100.0), 1)


def ai_explain(f: Finding) -> tuple[str, str, str]:
    """Return (priority_label, explanation, business_impact)."""
    score = f.risk_score
    if score >= 50:
        priority = "P0 — Immediate"
    elif score >= 30:
        priority = "P1 — This sprint"
    elif score >= 15:
        priority = "P2 — Next sprint"
    else:
        priority = "P3 — Backlog"

    explanations = {
        "CRITICAL": (
            f"This finding exposes sensitive data or grants unrestricted access. "
            f"On {f.cloud.upper()} resource '{f.resource}', the control {f.control} "
            f"is violated. Immediate containment is recommended before lateral movement "
            f"or data exfiltration can occur."
        ),
        "HIGH": (
            f"High-severity misconfiguration on {f.cloud.upper()} ({f.type}). "
            f"While not immediately public, the configuration significantly increases "
            f"attack surface and will fail most audit frameworks ({f.framework})."
        ),
        "MEDIUM": (
            f"Medium risk control failure ({f.control}). Remediation improves "
            f"defense-in-depth and reduces residual risk for compliance frameworks "
            f"including {f.framework}."
        ),
    }
    explanation = explanations.get(
        f.severity,
        f"Low-priority finding on {f.cloud.upper()}. Track and remediate as capacity allows.",
    )

    impact_map = {
        "aws": "Customer data residency & PCI/SOC 2 evidence packages at risk.",
        "azure": "Enterprise identity & workload compliance posture degraded.",
        "sap": "Mission-critical ERP integrity and segregation-of-duties at risk; audit findings likely.",
    }
    impact = impact_map.get(f.cloud, "General compliance posture impact.")

    return priority, explanation, impact


def enrich_findings(items: list[Finding]) -> list[Finding]:
    for f in items:
        f.risk_score = compute_risk_score(f)
        f.ai_priority, f.ai_explanation, f.business_impact = ai_explain(f)
    # Sort by risk_score descending
    items.sort(key=lambda x: x.risk_score, reverse=True)
    return items


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------
@app.on_event("startup")
def startup() -> None:
    global FINDINGS
    FINDINGS = enrich_findings(load_findings())


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
@app.get("/api/health")
def health():
    return {"status": "ok", "service": "ai-multicloud-compliance-poc", "time": datetime.now(timezone.utc).isoformat()}


@app.get("/api/findings")
def list_findings(
    cloud: Cloud | None = None,
    severity: Severity | None = None,
    min_score: float = 0.0,
):
    results = FINDINGS
    if cloud:
        results = [f for f in results if f.cloud == cloud]
    if severity:
        results = [f for f in results if f.severity == severity]
    if min_score > 0:
        results = [f for f in results if f.risk_score >= min_score]
    return {"count": len(results), "findings": results}


@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: str):
    for f in FINDINGS:
        if f.id == finding_id:
            return f
    return JSONResponse({"error": "not found"}, status_code=404)


@app.get("/api/stats", response_model=DashboardStats)
def stats():
    by_sev: dict[str, int] = {}
    by_cloud: dict[str, int] = {}
    for f in FINDINGS:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_cloud[f.cloud] = by_cloud.get(f.cloud, 0) + 1
    critical = by_sev.get("CRITICAL", 0)
    # Simple compliance score: 100 - weighted open findings
    penalty = sum(SEVERITY_WEIGHT.get(f.severity, 5) for f in FINDINGS) / 10
    score = max(0.0, round(100 - penalty, 1))
    return DashboardStats(
        total=len(FINDINGS),
        by_severity=by_sev,
        by_cloud=by_cloud,
        critical_open=critical,
        compliance_score=score,
        last_refresh=datetime.now(timezone.utc).isoformat(),
    )


@app.post("/api/remediate")
def remediate(req: RemediateRequest):
    target = next((f for f in FINDINGS if f.id == req.finding_id), None)
    if not target:
        return JSONResponse({"error": "finding not found"}, status_code=404)
    if target.status == "REMEDIATED":
        return {"message": "already remediated", "finding": target}

    # Simulate remediation
    target.status = "REMEDIATED"
    entry = {
        "finding_id": target.id,
        "title": target.title,
        "cloud": target.cloud,
        "approved_by": req.approved_by,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": "status set to REMEDIATED (PoC simulation)",
        "evidence": f"PoC evidence package generated for {target.id}",
    }
    REMEDIATION_LOG.append(entry)
    return {"message": "remediation recorded", "log": entry, "finding": target}


@app.get("/api/remediation-log")
def remediation_log():
    return {"count": len(REMEDIATION_LOG), "entries": REMEDIATION_LOG}


@app.get("/api/frameworks")
def frameworks():
    """Return unique frameworks and control counts."""
    fw: dict[str, int] = {}
    for f in FINDINGS:
        fw[f.framework] = fw.get(f.framework, 0) + 1
    return fw


# ---------------------------------------------------------------------------
# Dashboard (HTML)
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    stats_data = stats()
    findings_dicts = [f.model_dump() for f in FINDINGS]
    return templates.TemplateResponse(
        "dashboard.html",
        {
            "request": request,
            "stats": stats_data,
            "findings": FINDINGS,
            "findings_json": findings_dicts,
            "remediation_log": REMEDIATION_LOG,
        },
    )


# ---------------------------------------------------------------------------
# CLI helper
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
