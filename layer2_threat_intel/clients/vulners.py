import os
import requests
from typing import Dict, Any, List
from dotenv import load_dotenv

# --------------------------------------------------
# Load environment variables
# --------------------------------------------------
load_dotenv()
VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")

VULNERS_URL = "https://vulners.com/api/v3/search/lucene/"


# --------------------------------------------------
# Vulners Lookup (USED BY LAYER-2 ENRICHER)
# --------------------------------------------------
def lookup_vulners(
    service: str,
    version: str | None = None
) -> List[Dict[str, Any]]:
    """
    Query Vulners for vulnerabilities related to a service/version.

    Returns:
        List of normalized CVE dictionaries
    """

    if not VULNERS_API_KEY or not service:
        return []

    query = service
    if version:
        query += f" {version}"

    payload = {
        "query": query,
        "apiKey": VULNERS_API_KEY,
        "size": 10
    }

    try:
        r = requests.post(VULNERS_URL, json=payload, timeout=15)
        if not r.ok:
            return []

        data = r.json()
        results = data.get("data", {}).get("search", [])

        vulns: List[Dict[str, Any]] = []

        for item in results:
            source = item.get("_source", {})
            vulns.append({
                "cve_id": source.get("id"),
                "title": source.get("title"),
                "description": source.get("description"),
                "cvss_score": source.get("cvss", {}).get("score"),
                "cvss_vector": source.get("cvss", {}).get("vector"),
                "severity": source.get("cvss", {}).get("severity"),
                "source": "vulners"
            })

        return vulns

    except Exception:
        # 🔥 Layer-2 must NEVER crash backend
        return []
