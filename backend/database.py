import sqlite3
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime


# =================================================
# DATABASE LOCATION
# =================================================

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "cratip.db"


# =================================================
# CONNECTION
# =================================================

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


# =================================================
# INITIALIZE DATABASE
# =================================================

def init_db() -> None:
    """
    Initialize ALL backend tables.
    Safe to call multiple times.
    """
    conn = get_connection()
    cur = conn.cursor()

    # ---- USERS (future auth support) ----
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            role TEXT DEFAULT 'user'
        )
    """)

    # ---- SCANS (FULL PIPELINE STORAGE) ----
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT,
            scan_profile TEXT,
            targets TEXT,
            ports TEXT,
            layer1_json TEXT,
            layer2_json TEXT,
            layer3_json TEXT,
            created_at TEXT
        )
    """)

    # ---- ALERTS ----
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            severity TEXT,
            title TEXT,
            description TEXT,
            targets TEXT,
            created_at TEXT,
            acknowledged INTEGER DEFAULT 0
        )
    """)

    
    # ---- ALERTS ----
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            severity TEXT,
            title TEXT,
            description TEXT,
            targets TEXT,
            created_at TEXT,
            acknowledged INTEGER DEFAULT 0
        )
    """)

    # ---- AUDIT LOGS ----
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            action TEXT,
            details TEXT
        )
    """)

    conn.commit()
    conn.close()


# =================================================
# SCAN STATUS (IN-MEMORY, FAST)
# =================================================

_scan_status: Dict[str, Any] = {
    "state": "idle",           # idle | running | completed | failed
    "started_at": None,
    "finished_at": None
}

def set_scan_status(state: str) -> None:
    now = datetime.utcnow().isoformat()
    _scan_status["state"] = state

    if state == "running":
        _scan_status["started_at"] = now
        _scan_status["finished_at"] = None
    elif state in ("completed", "failed"):
        _scan_status["finished_at"] = now

def get_scan_status() -> Dict[str, Any]:
    return _scan_status.copy()


def get_scan_metadata() -> dict:
    """
    Returns latest scan metadata for dashboard header.
    SAFE: never raises even if table/schema changes.
    """
    try:

        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT
                scan_type,
                scan_profile,
                ports,
                created_at
            FROM scans
            ORDER BY created_at DESC
            LIMIT 1
        """)

        row = cur.fetchone()

        if not row:
            return {
                "scan_type": "N/A",
                "scan_profile": "N/A",
                "ports": "",
                "created_at": None,
            }

        return {
            "scan_type": row["scan_type"],
            "scan_profile": row["scan_profile"],
            "ports": row["ports"],
            "created_at": row["created_at"],
        }

    except Exception as e:
        # HARD FAIL PROTECTION — dashboard must never crash
        return {
            "scan_type": "Error",
            "scan_profile": "Unknown",
            "ports": "",
            "created_at": None,
            "error": str(e),
        }

    finally:
        if conn:
            conn.close()

# =================================================
# SAVE SCAN (DICT-ONLY, SAFE)
# =================================================

def save_scan(
    scan_type: str,
    scan_profile: str,
    targets: List[str],
    ports: Optional[str],
    layer1: Dict[str, Any],
    layer2: Optional[Dict[str, Any]] = None,
    layer3: Optional[Dict[str, Any]] = None
) -> None:
    """
    Store ONE scan batch.
    All layers stored as JSON DICTS.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO scans (
            scan_type,
            scan_profile,
            targets,
            ports,
            layer1_json,
            layer2_json,
            layer3_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_type,
            scan_profile,
            json.dumps(targets),
            ports,
            json.dumps(layer1),
            json.dumps(layer2) if layer2 else None,
            json.dumps(layer3) if layer3 else None,
            datetime.utcnow().isoformat()
        )
    )

    conn.commit()
    conn.close()


# =================================================
# FETCH LATEST SCAN (DICT)
# =================================================

def get_latest_scan() -> Dict[str, Any]:
    """
    Return latest scan with ALL layers.
    NEVER returns list.
    """
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT *
        FROM scans
        ORDER BY id DESC
        LIMIT 1
    """)

    row = cur.fetchone()
    conn.close()

    if not row:
        return {}

    return {
        "scan_type": row["scan_type"],
        "scan_profile": row["scan_profile"],
        "targets": json.loads(row["targets"] or "[]"),
        "ports": row["ports"],
        "created_at": row["created_at"],
        "layer1": json.loads(row["layer1_json"] or "{}"),
        "layer2": json.loads(row["layer2_json"] or "{}"),
        "layer3": json.loads(row["layer3_json"] or "{}"),
    }


# =================================================
# FLATTENED NMAP RESULTS (FOR DASHBOARD)
# =================================================

def get_nmap_rows() -> List[Dict[str, Any]]:
    """
    Flatten Layer-1 output for /nmap/results
    """
    scan = get_latest_scan()
    rows: List[Dict[str, Any]] = []

    layer1 = scan.get("layer1", {})
    
    # Handle both list and dict formats
    if isinstance(layer1, list):
        # Already flat list from scanner
        return layer1
    
    if isinstance(layer1, dict):
        services = layer1.get("services", [])
        if services:
            # Direct services list
            return services
        
        # Nested dict structure
        for host, host_data in layer1.items():
            if isinstance(host_data, dict):
                for svc in host_data.get("services", []):
                    rows.append({
                        "host": host,
                        "port": svc.get("port"),
                        "protocol": svc.get("protocol"),
                        "state": svc.get("state"),
                        "service": svc.get("service"),
                        "product": svc.get("product"),
                        "version": svc.get("version"),
                        "vulnerabilities": svc.get("vulnerabilities", 0),
                        "scan_profile": scan.get("scan_profile"),
                        "created_at": scan.get("created_at")
                    })

    return rows


# =================================================
# THREAT INTEL ACCESS
# =================================================

def get_threat_intel() -> List[Dict[str, Any]]:
    """Return threat intelligence data as list for dashboard"""
    scan = get_latest_scan()
    layer2 = scan.get("layer2", {})
    
    # Handle different layer2 structures
    if isinstance(layer2, dict):
        threat_intel_dict = layer2.get("threat_intel", {})
        
        # Convert dict to list format for dashboard
        intel_list = []
        for ip, intel_data in threat_intel_dict.items():
            if isinstance(intel_data, dict):
                intel_list.append({
                    "ip": ip,
                    **intel_data
                })
        
        return intel_list
    
    return []


# =================================================
# RISK SUMMARY ACCESS
# =================================================

def get_risk_summary() -> Dict[str, Any]:
    scan = get_latest_scan()
    layer3 = scan.get("layer3", {})
    
    # Calculate from assets if aggregated data not present
    assets = layer3.get("assets", [])
    
    if isinstance(layer3.get("risk"), dict):
        risk_data = layer3["risk"]
        return {
            "total_assets": risk_data.get("total_assets", len(assets)),
            "critical": risk_data.get("critical", 0),
            "high": risk_data.get("high", 0),
            "medium": risk_data.get("medium", 0),
            "low": risk_data.get("low", 0),
            "overall_score": risk_data.get("overall_score", 0),
            "generated_at": scan.get("created_at")
        }
    
    # Fallback: calculate from assets
    critical = sum(1 for a in assets if a.get("risk_level") == "CRITICAL")
    high = sum(1 for a in assets if a.get("risk_level") == "HIGH")
    medium = sum(1 for a in assets if a.get("risk_level") == "MEDIUM")
    low = sum(1 for a in assets if a.get("risk_level") == "LOW")
    
    return {
        "total_assets": len(assets),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "overall_score": layer3.get("overall_score", 0),
        "generated_at": scan.get("created_at")
    }


# =================================================
# ALERTS
# =================================================

def create_alert(
    alert_type: str,
    severity: str,
    title: str,
    description: str,
    targets: Optional[str] = None
) -> None:
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO alerts (
            alert_type,
            severity,
            title,
            description,
            targets,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            alert_type,
            severity,
            title,
            description,
            targets,
            datetime.utcnow().isoformat()
        )
    )

    conn.commit()
    conn.close()


def get_alerts() -> List[Dict[str, Any]]:
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT *
        FROM alerts
        ORDER BY created_at DESC
    """)

    rows = cur.fetchall()
    conn.close()

    return [dict(r) for r in rows]


# =================================================
# AUDIT LOGGING
# =================================================

def log_audit(
    audit_data: Dict[str, Any]
) -> None:
    conn = get_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO audit_logs (
            timestamp,
            username,
            action,
            details
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            audit_data.get("timestamp", datetime.utcnow().isoformat()),
            audit_data.get("username", "system"),
            audit_data.get("action", "UNKNOWN"),
            json.dumps(audit_data.get("details", {}))
        )
    )

    conn.commit()
    conn.close()

