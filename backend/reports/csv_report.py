import csv
from io import StringIO
from datetime import datetime
from typing import Dict, Any, List

from backend.database import get_latest_scan


# =================================================
# CSV REPORT GENERATOR
# =================================================
def generate_csv_report() -> str:
    """
    Generate CSV report from latest scan.
    Returns CSV content as string.
    """

    scan = get_latest_scan()
    if not scan:
        return ""

    layer1 = scan.get("layer1", {})
    layer2 = scan.get("layer2", {})
    layer3 = scan.get("layer3", {})

    services = layer1.get("services", [])
    intel = layer2.get("intel", [])
    risks = layer3.get("risk", [])

    # Risk lookup by host
    risk_map = {
        r.get("host"): r for r in risks if isinstance(r, dict)
    }

    # Intel lookup by host
    intel_map = {}
    for i in intel:
        host = i.get("host")
        intel_map.setdefault(host, 0)
        intel_map[host] += 1

    output = StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "timestamp",
        "host",
        "port",
        "service",
        "state",
        "product",
        "version",
        "vulnerability_count",
        "threat_score",
        "risk_level",
        "intel_hits",
    ])

    ts = datetime.utcnow().isoformat()

    for svc in services:
        host = svc.get("host")

        risk = risk_map.get(host, {})
        intel_hits = intel_map.get(host, 0)

        writer.writerow([
            ts,
            host,
            svc.get("port"),
            svc.get("service"),
            svc.get("state"),
            svc.get("product"),
            svc.get("version"),
            svc.get("vulnerabilities", 0),
            risk.get("risk_score", 0),
            risk.get("risk_level", "Unknown"),
            intel_hits,
        ])

    return output.getvalue()
