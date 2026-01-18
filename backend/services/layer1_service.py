# backend/services/layer1_service.py

from typing import List, Dict, Any, Optional
#from datetime import datetime


# --------------------------------------------------
# Lazy import (required for FastAPI reload stability)
# --------------------------------------------------
def _get_layer1_scanner():
    from layer1_scanning.scanner import scan_target
    return scan_target




# --------------------------------------------------
# PUBLIC API — CALLED BY ORCHESTRATOR ONLY
# --------------------------------------------------
def run_layer1_scan(
    targets: List[str],
    ports: Optional[str] = None,
    scan_profile: str = "Normal",
) -> Dict[str, Any]:
    """
    Executes Layer-1 (Nmap) scans and returns a NORMALIZED DICT.

    - No threat intel
    - No database
    - No side effects
    """

    scanner = _get_layer1_scanner()

    try:
        # scan_output is a flat list of service records
        scan_output = scanner(
            targets=targets,
            ports=ports,
            scan_profile=scan_profile,
        )

        # Return flat services list format
        return {
            "services": scan_output,
            "total_services": len(scan_output),
        }

    except Exception as e:
        print(f"Layer-1 scan failed: {e}")
        return {
            "services": [],
            "total_services": 0,
            "error": str(e)
        }
