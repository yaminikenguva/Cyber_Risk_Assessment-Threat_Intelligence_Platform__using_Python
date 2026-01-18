from typing import Dict, Any
import os
from dotenv import load_dotenv

from layer2_threat_intel.clients.virustotal import lookup_virustotal
from layer2_threat_intel.clients.shodan import lookup_shodan
from layer2_threat_intel.clients.vulners import lookup_vulners
from layer2_threat_intel.clients.nvd import lookup_nvd

# --------------------------------------------------
# Load API keys from .env
# --------------------------------------------------
load_dotenv()

API_KEYS = {
    "VIRUSTOTAL_API_KEY": os.getenv("VIRUSTOTAL_API_KEY"),
    "SHODAN_API_KEY": os.getenv("SHODAN_API_KEY"),
    "VULNERS_API_KEY": os.getenv("VULNERS_API_KEY"),
    "NVD_API_KEY": os.getenv("NVD_API_KEY"),
}


# --------------------------------------------------
# 🔥 REQUIRED ENTRYPOINT FOR BACKEND
# --------------------------------------------------
def enrich_layer1_results(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Layer-2 Threat Intelligence Enrichment

    Input:
        scan_data = output of Layer-1 (Nmap)

    Output:
        scan_data + threat_intel section
    """

    if not isinstance(scan_data, dict):
        return scan_data

    enriched = scan_data.copy()
    enriched["threat_intel"] = {}

    hosts = scan_data.get("data", {})

    if not isinstance(hosts, dict):
        return enriched

    for ip, host_data in hosts.items():
        services = host_data.get("services", [])

        enriched["threat_intel"][ip] = {
            "virustotal": lookup_virustotal(
                ip, API_KEYS.get("VIRUSTOTAL_API_KEY")
            ),
            "shodan": lookup_shodan(
                ip, API_KEYS.get("SHODAN_API_KEY")
            ),
            "vulners": [],
            "nvd": []
        }

        # Enrich per service (product/version based)
        for svc in services:
            product = svc.get("product") or svc.get("service")
            version = svc.get("version")

            keyword = f"{product} {version}".strip()

            if keyword:
                enriched["threat_intel"][ip]["vulners"].extend(
                    lookup_vulners(
                        keyword,
                        API_KEYS.get("VULNERS_API_KEY")
                    )
                )

                enriched["threat_intel"][ip]["nvd"].extend(
                    lookup_nvd(keyword)
                )

    return enriched
