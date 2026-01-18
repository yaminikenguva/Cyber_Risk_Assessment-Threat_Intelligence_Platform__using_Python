# backend/services/layer2_service.py

import os
from typing import Dict, Any, List
from dotenv import load_dotenv

from layer2_threat_intel.clients.vulners import lookup_vulners
from layer2_threat_intel.clients.virustotal import lookup_virustotal
from layer2_threat_intel.clients.shodan import lookup_shodan
from layer2_threat_intel.clients.nvd import lookup_nvd

# -------------------------------------------------
# Load API Keys
# -------------------------------------------------
load_dotenv()

VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
NVD_API_KEY = os.getenv("NVD_API_KEY")


# -------------------------------------------------
# Layer-2 Entry Point
# -------------------------------------------------
def run_layer2_enrichment(layer1_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Layer 2: Threat Intelligence Enrichment

    Input:
        Layer-1 flat services list

    Output:
        Enriched data with threat intel organized by host
    """

    # Get services list from layer1
    services = layer1_result.get("services", [])
    
    # Organize by host
    hosts_data = {}
    for svc in services:
        host = svc.get("host")
        if not host:
            continue
            
        if host not in hosts_data:
            hosts_data[host] = {"services": []}
        
        hosts_data[host]["services"].append(svc)
    
    # Build enriched structure
    enriched = {
        "data": hosts_data,
        "threat_intel": {}
    }
    
    # Enrich with threat intelligence
    for host in hosts_data.keys():
        enriched["threat_intel"][host] = {
            "virustotal": lookup_virustotal(host, VIRUSTOTAL_API_KEY),
            "shodan": lookup_shodan(host, SHODAN_API_KEY),
            "vulners": [],
            "nvd": []
        }
        
        # Service-level enrichment
        for svc in hosts_data[host]["services"]:
            service_name = svc.get("service") or svc.get("product") or ""
            version = svc.get("version") or ""
            
            if service_name:
                keyword = f"{service_name} {version}".strip()
                
                if VULNERS_API_KEY:
                    try:
                        vulners_data = lookup_vulners(keyword, VULNERS_API_KEY)
                        if vulners_data:
                            enriched["threat_intel"][host]["vulners"].extend(vulners_data)
                    except Exception:
                        pass
                
                try:
                    nvd_data = lookup_nvd(keyword)
                    if nvd_data:
                        enriched["threat_intel"][host]["nvd"].extend(nvd_data)
                except Exception:
                    pass
    
    return enriched
