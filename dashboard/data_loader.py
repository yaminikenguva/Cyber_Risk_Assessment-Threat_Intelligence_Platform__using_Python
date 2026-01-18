import requests
import pandas as pd
import streamlit as st
from typing import Any, Dict, Optional, List

# =================================================
# BACKEND API BASE
# =================================================

API_BASE = "http://127.0.0.1:8000"


# =================================================
# LOW LEVEL FETCH (SAFE)
# =================================================

def _fetch_json(endpoint: str) -> Optional[Any]:
    """
    Fetch JSON from backend.
    NEVER raises exception to UI.
    """
    try:
        r = requests.get(
            f"{API_BASE}{endpoint}",
            timeout=10
        )
        if r.ok:
            return r.json()
    except Exception:
        pass
    return None


# =================================================
# GENERIC LOAD (🔥 BACKWARD COMPAT)
# =================================================

def load(endpoint: str,refresh_key:Any=None):
    """
    Generic loader used across dashboard pages.

    Returns:
    - pd.DataFrame if list-like
    - dict if object-like
    - None if empty / failed
    """
    data = _fetch_json(endpoint)

    if data is None:
        return None

    # ---- list → DataFrame ----
    if isinstance(data, list):
        # if len(data) == 0:
        #     return pd.DataFrame()
        # return pd.DataFrame(data)
        return pd.DataFrame(data) if len(data)> 0 else pd.DataFrame()

    # ---- dict → return as-is ----
    if isinstance(data, dict):
        return data

    return None


# =================================================
# SCAN METADATA (HEADER)
# =================================================

@st.cache_data(show_spinner=False, ttl=30)
def load_scan_metadata(refresh_key:Any=None) -> Dict[str, Any]:
    """
    Safe metadata loader.
    Used in dashboard header.
    """
    data = _fetch_json("/scan/metadata")
    return data if isinstance(data, dict) else {}


# =================================================
# SCAN STATUS
# =================================================

def load_scan_status() -> str:
    """
    Returns scan state:
    idle | running | completed | failed
    """
    data = _fetch_json("/scan/status")
    if isinstance(data, dict):
        return data.get("state", "idle")
    return "idle"


# =================================================
# NMAP RESULTS (FLAT TABLE)
# =================================================

def load_nmap_results() -> pd.DataFrame:
    """
    Load flattened Nmap results.
    Guaranteed DataFrame.
    """
    data = _fetch_json("/nmap/results")

    if isinstance(data, list):
        return pd.DataFrame(data)

    return pd.DataFrame()


# =================================================
# THREAT INTELLIGENCE
# =================================================

def load_threat_intel() -> pd.DataFrame:
    """
    Load Layer-2 threat intelligence.
    """
    data = _fetch_json("/threat/intel")

    if isinstance(data, list):
        return pd.DataFrame(data)

    return pd.DataFrame()


# =================================================
# RISK SUMMARY
# =================================================

def load_risk_summary() -> Dict[str, Any]:
    """
    Load Layer-3 risk summary.
    Always returns dict.
    """
    data = _fetch_json("/risk/summary")
    return data if isinstance(data, dict) else {}


# =================================================
# ALERTS
# =================================================

def load_alerts() -> pd.DataFrame:
    """
    Load active alerts.
    """
    data = _fetch_json("/alerts")

    if isinstance(data, list):
        return pd.DataFrame(data)

    return pd.DataFrame()


# =================================================
# REPORTS
# =================================================

def load_latest_report() -> Dict[str, Any]:
    """
    Load latest report metadata.
    """
    data = _fetch_json("/reports/latest")
    return data if isinstance(data, dict) else {}


# =================================================
# SAFE HELPERS
# =================================================

def ensure_dataframe(obj: Any) -> pd.DataFrame:
    """
    Convert unknown object into safe DataFrame.
    """
    if isinstance(obj, pd.DataFrame):
        return obj
    if isinstance(obj, list):
        return pd.DataFrame(obj)
    return pd.DataFrame()


def ensure_dict(obj: Any) -> Dict[str, Any]:
    """
    Convert unknown object into safe dict.
    """
    if isinstance(obj, dict):
        return obj
    return {}
