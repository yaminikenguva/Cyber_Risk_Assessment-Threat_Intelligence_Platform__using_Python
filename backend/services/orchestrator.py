# backend/services/orchestrator.py

from typing import List, Dict, Any
from datetime import datetime

from backend.services.layer1_service import run_layer1_scan
from backend.services.layer2_service import run_layer2_enrichment
from backend.services.layer3_service import run_layer3_scoring
from backend.database import save_scan, set_scan_status

def run_full_pipeline(
    targets: List[str],
    ports: str | None,
    scan_profile: str,
    scan_type: str = "nmap"
) -> Dict[str, Any]:
    """
    MASTER ORCHESTRATOR
    Layer1 → Layer2 → Layer3 → DB
    """

    set_scan_status("running")

    try:
        # ---------- LAYER 1 ----------
        
        layer1_results = run_layer1_scan(
            targets=targets,
            ports=ports,
            scan_profile=scan_profile
        )

        # ---------- LAYER 2 ----------
        layer2_results = run_layer2_enrichment(layer1_results)

        # ---------- LAYER 3 ----------
        layer3_results = run_layer3_scoring(layer2_results)

        final_output = {
            "scan_type": scan_type,
            "scan_profile": scan_profile,
            "timestamp": datetime.utcnow().isoformat(),
            "layer1": layer1_results,
            "layer2": layer2_results,
            "layer3": layer3_results,
        }

        save_scan(
            scan_type=scan_type,
            scan_profile=scan_profile,
            # timestamp=datetime.utcnow().isoformat(),
            targets=targets,
            ports=ports,
            layer1=layer1_results,
            layer2=layer2_results,
            layer3=layer3_results,
        )

        set_scan_status("completed")
        return final_output

    except Exception as e:
        set_scan_status("failed")
        raise e
