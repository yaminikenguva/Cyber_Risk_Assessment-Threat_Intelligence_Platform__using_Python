# Risk score engine
from typing import Dict, Any, List
from datetime import datetime

# ===============================
# CONFIGURATION
# ===============================

HIGH_RISK_PORTS = {22, 3389}
MAX_SCORE = 100


# ===============================
# CORE RISK SCORING
# ===============================

def _score_service(service: Dict[str, Any]) -> int:
    score = 0

    # Open port
    if service.get("state") == "open":
        score += 2

    # Vulnerabilities
    vulns = service.get("vulnerabilities", 0)
    score += vulns * 4

    # High-risk ports
    if service.get("port") in HIGH_RISK_PORTS:
        score += 5

    return score


def _score_threat_intel(intel: Dict[str, Any]) -> int:
    score = 0

    for source, data in intel.items():
        if not isinstance(data, dict):
            continue

        if data.get("malicious") is True:
            score += 10

        if data.get("risk_level") in ("high", "critical"):
            score += 8

    return score


def _normalize(score: int) -> int:
    return min(score, MAX_SCORE)


def _risk_level(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"


# ===============================
# PUBLIC ENTRYPOINT (BACKEND CALLS THIS)
# ===============================

def process_layer2_to_layer3(
    layer2_data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Input  : Layer-2 enriched scan data (DICT)
    Output : Risk-scored Layer-3 results (DICT)
    """

    assets: List[Dict[str, Any]] = []
    
    data = layer2_data.get("data", {})
    threat_intel = layer2_data.get("threat_intel", {})

    for ip, host in data.items():
        host_score = 0
        services = host.get("services", [])

        # Score services
        for svc in services:
            host_score += _score_service(svc)

        # Threat intel contribution
        host_score += _score_threat_intel(
            threat_intel.get(ip, {})
        )

        normalized = _normalize(host_score)

        assets.append({
            "ip": ip,
            "hostname": host.get("hostname", ""),
            "risk_score": normalized,
            "risk_level": _risk_level(normalized),
            "open_ports": len([
                s for s in services if s.get("state") == "open"
            ]),
            "vulnerabilities": sum(
                s.get("vulnerabilities", 0) for s in services
            ),
            "services": services,
            "threat_intel": threat_intel.get(ip, {}),
        })
    
    # Aggregate statistics
    critical = sum(1 for a in assets if a["risk_level"] == "CRITICAL")
    high = sum(1 for a in assets if a["risk_level"] == "HIGH")
    medium = sum(1 for a in assets if a["risk_level"] == "MEDIUM")
    low = sum(1 for a in assets if a["risk_level"] == "LOW")
    
    total_score = sum(a["risk_score"] for a in assets)
    overall_score = total_score // len(assets) if assets else 0

    return {
        "generated_at": datetime.utcnow().isoformat(),
        "assets": assets,
        "risk": {
            "total_assets": len(assets),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "overall_score": overall_score,
        }
    }
