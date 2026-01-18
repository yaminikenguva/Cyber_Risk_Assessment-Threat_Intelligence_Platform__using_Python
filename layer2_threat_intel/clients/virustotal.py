# layer2_threat_intel/clients/virustotal.py

import requests
from typing import Dict, Any, Optional

VT_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"


def lookup_virustotal(
    ip: str,
    api_key: Optional[str],
    timeout: int = 10
) -> Dict[str, Any]:
    """
    Query VirusTotal for IP reputation.

    INPUT:
        ip       : Target IP address
        api_key  : VirusTotal API key (can be None)
        timeout  : Request timeout (seconds)

    OUTPUT (DICT ONLY):
        {
            "malicious": int,
            "suspicious": int,
            "harmless": int,
            "undetected": int,
            "reputation": int,
            "country": str,
            "asn": str,
            "network": str,
            "source": "virustotal"
        }
    """

    # -------------------------------
    # API key missing → safe skip
    # -------------------------------
    if not api_key:
        return {
            "source": "virustotal",
            "status": "skipped",
            "reason": "API key not provided"
        }

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json"
    }

    try:
        response = requests.get(
            f"{VT_BASE_URL}/{ip}",
            headers=headers,
            timeout=timeout
        )

        if response.status_code != 200:
            return {
                "source": "virustotal",
                "status": "error",
                "http_status": response.status_code
            }

        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})

        stats = attributes.get("last_analysis_stats", {})

        return {
            "source": "virustotal",
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
            "reputation": int(attributes.get("reputation", 0)),
            "country": attributes.get("country", ""),
            "asn": str(attributes.get("asn", "")),
            "network": attributes.get("network", "")
        }

    except requests.Timeout:
        return {
            "source": "virustotal",
            "status": "timeout"
        }

    except Exception as e:
        return {
            "source": "virustotal",
            "status": "failed",
            "error": str(e)
        }
