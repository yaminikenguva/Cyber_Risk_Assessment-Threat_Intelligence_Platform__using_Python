# Alert rules
from datetime import datetime
from typing import List, Dict, Any, Optional
import traceback

# =================================================
# INTERNAL IMPORTS
# =================================================
from backend.database import (
    save_scan,
    set_scan_status,
    log_audit,
    create_alert,
)

# Lazy imports to avoid startup crashes
def _layer1_scan():
    from layer1_scanning.scanner import scan_target
    return scan_target

def _layer2_enrich():
    from layer2_threat_intel.enricher import enrich_layer1_results
    return enrich_layer1_results

def _layer3_score():
    from layer3_risk_scoring.scorer import process_layer2_to_layer3
    return process_layer2_to_layer3


# =================================================
# ALERT CONFIGURATION
# =================================================
ALERT_THRESHOLDS = {
    "CRITICAL_RISK_SCORE": 80,
    "HIGH_RISK_SCORE": 60,
    "CRITICAL_VULNERABILITIES": 5,
    "HIGH_RISK_PORTS": {22, 3389, 445, 1433, 3306},
    "MALICIOUS_IP_THRESHOLD": 3,
}


# =================================================
# ALERT GENERATION LOGIC
# =================================================
def generate_alerts_from_scan(
    layer1: Dict[str, Any],
    layer2: Dict[str, Any],
    layer3: Dict[str, Any],
    targets: List[str],
) -> List[Dict[str, Any]]:
    """
    Analyze scan results and generate alerts for high-risk findings.
    
    Args:
        layer1: Nmap scan results
        layer2: Threat intelligence data
        layer3: Risk scoring results
        targets: List of scanned targets
    
    Returns:
        List of generated alerts
    """
    alerts = []
    
    # =================================================
    # ALERT 1: Critical Risk Score
    # =================================================
    if isinstance(layer3, dict):
        risk_data = layer3.get("risk", {})
        if isinstance(risk_data, dict):
            overall_score = risk_data.get("overall_score", 0)
            critical_count = risk_data.get("critical", 0)
            high_count = risk_data.get("high", 0)
            
            if overall_score >= ALERT_THRESHOLDS["CRITICAL_RISK_SCORE"]:
                alert = {
                    "alert_type": "CRITICAL_RISK_SCORE",
                    "severity": "CRITICAL",
                    "title": f"Critical Risk Score Detected: {overall_score}/100",
                    "description": f"Overall risk score ({overall_score}) exceeds critical threshold. "
                                 f"Found {critical_count} critical and {high_count} high-risk issues.",
                    "targets": ", ".join(targets),
                }
                alerts.append(alert)
                create_alert(**alert)
            
            elif overall_score >= ALERT_THRESHOLDS["HIGH_RISK_SCORE"]:
                alert = {
                    "alert_type": "HIGH_RISK_SCORE",
                    "severity": "HIGH",
                    "title": f"High Risk Score Detected: {overall_score}/100",
                    "description": f"Overall risk score ({overall_score}) exceeds high threshold. "
                                 f"Found {critical_count} critical and {high_count} high-risk issues.",
                    "targets": ", ".join(targets),
                }
                alerts.append(alert)
                create_alert(**alert)
    
    # =================================================
    # ALERT 2: Critical Vulnerabilities
    # =================================================
    if isinstance(layer1, dict):
        services = layer1.get("services", [])
        total_vulns = 0
        
        for svc in services:
            if isinstance(svc, dict):
                # Handle both formats: vulnerabilities as int or list
                vulns = svc.get("vulnerabilities", 0)
                if isinstance(vulns, list):
                    total_vulns += len(vulns)
                elif isinstance(vulns, int):
                    total_vulns += vulns
        
        if total_vulns >= ALERT_THRESHOLDS["CRITICAL_VULNERABILITIES"]:
            alert = {
                "alert_type": "MULTIPLE_VULNERABILITIES",
                "severity": "HIGH",
                "title": f"{total_vulns} Vulnerabilities Detected",
                "description": f"Scan identified {total_vulns} vulnerabilities across {len(services)} services. "
                             f"Immediate review recommended.",
                "targets": ", ".join(targets),
            }
            alerts.append(alert)
            create_alert(**alert)
    
    # =================================================
    # ALERT 3: High-Risk Ports Exposed
    # =================================================
    if isinstance(layer1, dict):
        services = layer1.get("services", [])
        exposed_high_risk = []
        
        for svc in services:
            if isinstance(svc, dict) and svc.get("state") == "open":
                port = svc.get("port")
                if port in ALERT_THRESHOLDS["HIGH_RISK_PORTS"]:
                    host = svc.get("host", "unknown")
                    service = svc.get("service", "unknown")
                    exposed_high_risk.append(f"{host}:{port} ({service})")
        
        if exposed_high_risk:
            alert = {
                "alert_type": "HIGH_RISK_PORTS_EXPOSED",
                "severity": "HIGH",
                "title": f"{len(exposed_high_risk)} High-Risk Ports Exposed",
                "description": f"Critical ports detected: {', '.join(exposed_high_risk[:5])}. "
                             f"These ports are common attack vectors.",
                "targets": ", ".join(targets),
            }
            alerts.append(alert)
            create_alert(**alert)
    
    # =================================================
    # ALERT 4: Malicious IP Detected
    # =================================================
    if isinstance(layer2, dict):
        intel_data = layer2.get("intel", {})
        if isinstance(intel_data, dict):
            threat_intel = intel_data.get("threat_intel", {})
            
            for ip, intel in threat_intel.items():
                if isinstance(intel, dict):
                    # Check VirusTotal
                    vt = intel.get("virustotal", {})
                    if isinstance(vt, dict):
                        malicious = vt.get("malicious", 0)
                        
                        if malicious >= ALERT_THRESHOLDS["MALICIOUS_IP_THRESHOLD"]:
                            alert = {
                                "alert_type": "MALICIOUS_IP",
                                "severity": "CRITICAL",
                                "title": f"Malicious IP Detected: {ip}",
                                "description": f"IP {ip} flagged by {malicious} security vendors as malicious. "
                                             f"Immediate investigation required.",
                                "targets": ip,
                            }
                            alerts.append(alert)
                            create_alert(**alert)
                    
                    # Check Shodan for vulnerabilities
                    shodan = intel.get("shodan", {})
                    if isinstance(shodan, dict):
                        vulns = shodan.get("vulnerabilities", [])
                        if len(vulns) > 5:
                            alert = {
                                "alert_type": "SHODAN_VULNERABILITIES",
                                "severity": "HIGH",
                                "title": f"{len(vulns)} Vulnerabilities Found on {ip}",
                                "description": f"Shodan detected {len(vulns)} known vulnerabilities on {ip}. "
                                             f"Public exposure confirmed.",
                                "targets": ip,
                            }
                            alerts.append(alert)
                            create_alert(**alert)
    
    # =================================================
    # ALERT 5: Unusual Activity Pattern
    # =================================================
    if isinstance(layer1, dict):
        services = layer1.get("services", [])
        
        # Group by host
        host_services = {}
        for svc in services:
            if isinstance(svc, dict):
                host = svc.get("host", "unknown")
                if host not in host_services:
                    host_services[host] = []
                host_services[host].append(svc)
        
        # Check for hosts with many open ports
        for host, svcs in host_services.items():
            open_ports = [s for s in svcs if s.get("state") == "open"]
            
            if len(open_ports) > 20:
                alert = {
                    "alert_type": "UNUSUAL_PORT_ACTIVITY",
                    "severity": "MEDIUM",
                    "title": f"Unusual Port Activity on {host}",
                    "description": f"Host {host} has {len(open_ports)} open ports. "
                                 f"This may indicate a compromised system or misconfiguration.",
                    "targets": host,
                }
                alerts.append(alert)
                create_alert(**alert)
    
    return alerts


# =================================================
# MAIN ORCHESTRATOR
# =================================================
def run_full_scan_pipeline(
    targets: List[str],
    ports: Optional[str],
    scan_profile: str,
) -> Dict[str, Any]:
    """
    FULL PIPELINE ORCHESTRATOR

    Flow:
    Dashboard
      → Backend
        → Layer1 (Nmap)
        → Layer2 (Threat Intel)
        → Layer3 (Risk Scoring)
        → Database
        → Alerts
        → Dashboard APIs
    """

    scan_id = f"scan-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    result: Dict[str, Any] = {
        "scan_id": scan_id,
        "scan_type": "nmap",
        "scan_profile": scan_profile,
        "targets": targets,
        "started_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "layer1": {},
        "layer2": {},
        "layer3": {},
        "errors": [],
    }

    set_scan_status("running")

    # =================================================
    # 🔵 LAYER 1 — AUTOMATED SCANNING
    # =================================================
    try:
        scan_target_fn = _layer1_scan()
        layer1_output = scan_target_fn(
            targets=targets,
            ports=ports,
            scan_profile=scan_profile,
        )

        # Layer1 MUST return a LIST of rows (flat)
        if not isinstance(layer1_output, list):
            raise ValueError("Layer1 output must be a list")

        result["layer1"] = {
            "services": layer1_output,
            "total_services": len(layer1_output),
        }

    except Exception as e:
        result["errors"].append(
            f"Layer1 failed: {str(e)}"
        )
        traceback.print_exc()

    # =================================================
    # 🟢 LAYER 2 — THREAT INTELLIGENCE
    # =================================================
    try:
        if result["layer1"].get("services"):
            enrich_fn = _layer2_enrich()
            # Layer2 expects dict with 'data' key
            layer1_data = {"data": {}}
            for svc in result["layer1"]["services"]:
                host = svc.get("host")
                if host not in layer1_data["data"]:
                    layer1_data["data"][host] = {"services": []}
                layer1_data["data"][host]["services"].append(svc)
            
            layer2_output = enrich_fn(layer1_data)

            result["layer2"] = {
                "intel": layer2_output,
                "enriched": True,
            }
        else:
            result["layer2"] = {"enriched": False}

    except Exception as e:
        result["errors"].append(
            f"Layer2 failed: {str(e)}"
        )
        traceback.print_exc()
        result["layer2"] = {"enriched": False}

    # =================================================
    # 🟡 LAYER 3 — RISK SCORING
    # =================================================
    try:
        if result["layer2"].get("intel"):
            score = _layer3_score()
            layer3_output = score(result["layer2"]["intel"])

            result["layer3"] = {
                "risk": layer3_output,
                "scored": True,
            }
        else:
            result["layer3"] = {"scored": False}

    except Exception as e:
        result["errors"].append(
            f"Layer3 failed: {str(e)}"
        )
        traceback.print_exc()
        result["layer3"] = {"scored": False}

    # =================================================
    # 🔴 STORE RESULTS (ONCE)
    # =================================================
    result["completed_at"] = datetime.utcnow().isoformat()

    try:
        save_scan(
            scan_type="nmap",
            scan_profile=scan_profile,
            targets=targets,
            ports=ports,
            layer1=result.get("layer1", {}),
            layer2=result.get("layer2", {}),
            layer3=result.get("layer3", {}),
        )
        set_scan_status("completed")

    except Exception as e:
        set_scan_status("failed")
        result["errors"].append(f"DB save failed: {e}")
        traceback.print_exc()

    # =================================================
    # 🚨 GENERATE ALERTS
    # =================================================
    try:
        alerts = generate_alerts_from_scan(
            layer1=result.get("layer1", {}),
            layer2=result.get("layer2", {}),
            layer3=result.get("layer3", {}),
            targets=targets,
        )
        result["alerts_generated"] = len(alerts)
        
        if alerts:
            print(f"🚨 Generated {len(alerts)} alerts")
    
    except Exception as e:
        result["errors"].append(f"Alert generation failed: {e}")
        traceback.print_exc()

    # =================================================
    # 📜 AUDIT LOG
    # =================================================
    log_audit(
        {
            "timestamp": datetime.utcnow().isoformat(),
            "username": "dashboard-user",
            "action": "SCAN_EXECUTED",
            "details": {
                "scan_id": scan_id,
                "targets": targets,
                "profile": scan_profile,
                "errors": result["errors"],
            },
        }
    )

    return result
