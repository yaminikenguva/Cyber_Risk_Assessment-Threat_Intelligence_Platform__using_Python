from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime
import ipaddress

# =================================================
# INTERNAL IMPORTS
# =================================================

from backend.database import (
    init_db,
    save_scan,
    get_latest_scan,
    get_scan_metadata,
    set_scan_status,
    get_scan_status,
    log_audit,
    get_alerts,
)

from backend.services.orchestrator import run_full_pipeline
from backend.alerts import run_full_scan_pipeline
from backend.config import validate_config

# =================================================
# FASTAPI APP
# =================================================

app = FastAPI(
    title="Cyber Risk Assessment Backend",
    version="1.0.0",
)

# =================================================
# REQUEST MODELS
# =================================================

class ScanFilters(BaseModel):
    cidr: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None


class ScanRequest(BaseModel):
    targets: Optional[List[str]] = None
    ports: Optional[str] = None
    scan_profile: str = "Normal"
    filters: Optional[ScanFilters] = None


# =================================================
# STARTUP
# =================================================

@app.on_event("startup")
def startup():
    init_db()

    warnings = validate_config()
    if warnings:
        print("⚠️ Config warnings:")
        for w in warnings:
            print(" -", w)
    else:
        print("✅ Configuration OK")

    set_scan_status("idle")


# =================================================
# HEALTH
# =================================================


@app.get("/health")
def health():
    return {"status": "ok"}


# =================================================
# SCAN METADATA
# =================================================

@app.get("/scan/metadata")
def scan_metadata():
    meta = get_scan_metadata()
    return {
        "scan_type": meta.get("scan_type", "nmap"),
        "target": meta.get("target"),
        "ports": meta.get("ports"),
        "created_at": meta.get("created_at"),
        "engine": "CRATIP Layered Scanner",
    }


# =================================================
# SCAN STATUS
# =================================================

@app.get("/scan/status")
def scan_status():
    return get_scan_status()


# =================================================
# TARGET FILTERING (CIDR)
# =================================================

def filter_targets(targets: List[str], filters: Optional[ScanFilters]) -> List[str]:
    if not filters or not filters.cidr:
        return targets

    try:
        network = ipaddress.ip_network(filters.cidr, strict=False)
    except ValueError:
        return targets

    filtered = []
    for t in targets:
        try:
            if ipaddress.ip_address(t) in network:
                filtered.append(t)
        except ValueError:
            filtered.append(t)

    return filtered


# =================================================
# BACKGROUND SCAN PIPELINE
# =================================================

def run_scan_pipeline(
    targets: List[str],
    ports: Optional[str],
    scan_profile: str,
):
    """
    Layer 1 → Layer 2 → Layer 3 → Store → Alerts → Audit
    """

    set_scan_status("running")

    try:
        # ---------------- FULL PIPELINE ----------------
        final_result: Dict[str, Any] = run_full_pipeline(
            targets=targets,
            ports=ports,
            scan_profile=scan_profile,
        )

        # ---------------- STORE ----------------
        save_scan(
            scan_type="nmap",
            scan_profile=scan_profile,
            targets=targets,
            ports=ports,
            layer1=final_result.get("layer1", {}),
            layer2=final_result.get("layer2", {}),
            layer3=final_result.get("layer3", {}),
        )

        # ---------------- AUDIT ----------------
        log_audit({
            "timestamp": datetime.utcnow().isoformat(),
            "username": "dashboard-user",
            "action": "SCAN_COMPLETED",
            "details": {
                "targets": targets,
                "ports": ports,
                "profile": scan_profile,
            },
        })

        set_scan_status("completed")
        print("✅ Scan completed successfully")

    except Exception as e:
        set_scan_status("failed")
        print("❌ Scan failed:", e)


# =================================================
# START SCAN
# =================================================

@app.post("/scan/start")
def start_scan(payload: ScanRequest, background_tasks: BackgroundTasks):
    """
    Accepts:
    - targets OR ports OR uploaded targets (dashboard handles input)
    """

    if not payload.targets:
        raise HTTPException(status_code=400, detail="No targets provided")

    targets = filter_targets(payload.targets, payload.filters)

    if not targets:
        raise HTTPException(status_code=400, detail="No valid targets")

    background_tasks.add_task(
        run_scan_pipeline,
        targets,
        payload.ports,
        payload.scan_profile,
    )

    return {
        "status": "started",
        "targets": targets,
        "scan_profile": payload.scan_profile,
    }


# =================================================
# NMAP RESULTS (FLATTENED FOR DASHBOARD)
# =================================================

@app.get("/nmap/results")
def nmap_results():
    """Return flattened Nmap scan results"""
    from backend.database import get_nmap_rows
    return get_nmap_rows()


# =================================================
# THREAT INTELLIGENCE (LAYER 2)
# =================================================

@app.get("/threat/intel")
def threat_intel():
    """Return threat intelligence data"""
    from backend.database import get_threat_intel
    return get_threat_intel()


# =================================================
# RISK SUMMARY (LAYER 3)
# =================================================

@app.get("/risk/summary")
def risk_summary():
    """Return risk scoring summary"""
    from backend.database import get_risk_summary
    return get_risk_summary()


# =================================================
# REPORTS
# =================================================

@app.get("/reports/latest")
def latest_report():
    data = get_latest_scan()

    if not data:
        return {}

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "scan_profile": data.get("scan_profile"),
        "risk_summary": data.get("layer3", {}),
        "recommendations": data.get("recommendations", []),
    }


# =================================================
# ALERTS
# =================================================

@app.get("/alerts")
def alerts():
    """
    Retrieve all alerts ordered by most recent.
    """
    return get_alerts()


@app.get("/alerts/active")
def active_alerts():
    """
    Retrieve only unacknowledged alerts.
    """
    all_alerts = get_alerts()
    return [a for a in all_alerts if not a.get("acknowledged", 0)]


@app.get("/alerts/stats")
def alert_stats():
    """
    Get alert statistics for dashboard metrics.
    """
    all_alerts = get_alerts()
    
    total = len(all_alerts)
    critical = sum(1 for a in all_alerts if a.get("severity") == "CRITICAL")
    high = sum(1 for a in all_alerts if a.get("severity") == "HIGH")
    medium = sum(1 for a in all_alerts if a.get("severity") == "MEDIUM")
    active = sum(1 for a in all_alerts if not a.get("acknowledged", 0))
    
    return {
        "total": total,
        "active": active,
        "critical": critical,
        "high": high,
        "medium": medium,
        "acknowledged": total - active,
    }




