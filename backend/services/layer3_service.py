# backend/services/layer3_service.py

import os
from typing import Dict, Any, List
from statistics import mean
from dotenv import load_dotenv

from layer3_risk_scoring.scorer import _score_service
from layer3_risk_scoring.ai_reasoner import generate_ai_analysis


# -------------------------------------------------
# Load Environment
# -------------------------------------------------
load_dotenv()
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")


# -------------------------------------------------
# Risk Level Helper
# -------------------------------------------------
def _score_to_level(score: float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


# -------------------------------------------------
# Layer-3 Entry Point
# -------------------------------------------------
def run_layer3_scoring(layer2_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Layer 3: Risk Scoring & Normalization

    Input:
        Layer-2 enriched data

    Output:
        Asset-level risk scores + global summary
    """
    
    from layer3_risk_scoring.scorer import process_layer2_to_layer3
    
    # Use the scorer module directly
    return process_layer2_to_layer3(layer2_result)
    # Score Each Vulnerability
    # -------------------------------------------------
    for v in vulns:
        host = v.get("host", "unknown")

        # Score CVE / finding
        score = _score_service(v)

        host_scores.setdefault(host, []).append(score)

        # Optional AI explanation
        explanation = ""
        if OPENROUTER_API_KEY:
            try:
                explanation = generate_ai_analysis(v, score)
            except Exception:
                explanation = ""

        detailed_results.append({
            "host": host,
            "port": v.get("port"),
            "service": v.get("service"),
            "score": score,
            "risk_level": _score_to_level(score),
            "summary": explanation,
        })

    # -------------------------------------------------
    # Aggregate Host-Level Risk
    # -------------------------------------------------
    host_risk_summary: List[Dict[str, Any]] = []

    for host, scores in host_scores.items():
        avg_score = round(mean(scores), 2)

        host_risk_summary.append({
            "host": host,
            "risk_score": avg_score,
            "risk_level": _score_to_level(avg_score),
            "total_findings": len(scores),
        })

    # -------------------------------------------------
    # Global Risk Summary
    # -------------------------------------------------
    global_score = (
        round(mean([h["risk_score"] for h in host_risk_summary]), 2)
        if host_risk_summary else 0
    )

    return {
        "scan_profile": layer2_result.get("scan_profile"),
        "risk_score": global_score,
        "risk_level": _score_to_level(global_score),
        "hosts": host_risk_summary,
        "details": detailed_results,
    }
