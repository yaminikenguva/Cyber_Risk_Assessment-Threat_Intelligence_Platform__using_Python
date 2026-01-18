import os
import requests
from typing import Dict, Any, List
from dotenv import load_dotenv

# --------------------------------------------------
# Load environment variables
# --------------------------------------------------
load_dotenv()
NVD_API_KEY = os.getenv("NVD_API_KEY")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# --------------------------------------------------
# NVD Lookup (USED BY LAYER-2 ENRICHER)
# --------------------------------------------------
def lookup_nvd(
    keyword: str,
    max_results: int = 10
) -> List[Dict[str, Any]]:
    """
    Query NVD for CVEs related to a keyword (service / product).

    Returns:
        List of normalized CVE dictionaries
    """

    if not keyword:
        return []

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results
    }

    try:
        r = requests.get(
            NVD_URL,
            headers=headers,
            params=params,
            timeout=20
        )

        if not r.ok:
            return []

        data = r.json()
        vulns: List[Dict[str, Any]] = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            metrics = cve.get("metrics", {})

            # Prefer CVSS v3.1
            cvss = None
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]

            vulns.append({
                "cve_id": cve.get("id"),
                "title": cve.get("id"),
                "description": (
                    cve.get("descriptions", [{}])[0].get("value")
                ),
                "cvss_score": cvss.get("baseScore") if cvss else None,
                "cvss_vector": cvss.get("vectorString") if cvss else None,
                "severity": cvss.get("baseSeverity") if cvss else None,
                "source": "nvd"
            })

        return vulns

    except Exception:
        # 🔥 Never crash Layer-2
        return []
