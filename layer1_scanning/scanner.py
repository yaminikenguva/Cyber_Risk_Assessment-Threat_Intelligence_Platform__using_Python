# Nmap logic (FLAT output)
# MAIN ENTRY (BACKEND imports this)

import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional

from .utils import log, NMAP_ARGUMENTS


# =================================================
# BACKEND ENTRYPOINT (DO NOT CHANGE NAME)
# =================================================
def scan_target(
    targets: List[str],
    ports: Optional[str] = None,
    scan_profile: str = "Normal"
) -> List[Dict]:
    """
    🔵 Layer-1 Scanner
    RETURNS: FLAT LIST (required by backend & dashboard)
    """

    rows: List[Dict] = []

    for target in targets:
        log(f"Starting Nmap scan for {target}", "INFO")

        command = [
            "nmap",
            *NMAP_ARGUMENTS,
            "-oX", "-"
        ]

        if ports:
            command.extend(["-p", ports])
        else:
            command.extend(["--top-ports", "1000"])

        command.append(target)

        try:
            xml_output = subprocess.check_output(
                command,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=600
            )
        except Exception as e:
            log(f"Nmap failed for {target}: {e}", "ERROR")
            continue

        rows.extend(
            _parse_nmap_xml(
                xml_output,
                target=target,
                scan_profile=scan_profile
            )
        )

    log(f"Layer-1 completed → {len(rows)} rows")
    return rows


# =================================================
# XML → FLAT ROWS
# =================================================
def _parse_nmap_xml(
    xml_data: str,
    target: str,
    scan_profile: str
) -> List[Dict]:

    results: List[Dict] = []

    root = ET.fromstring(xml_data)

    for host in root.findall("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue

        ip = addr_el.attrib.get("addr")

        for port in host.findall("ports/port"):
            state_el = port.find("state")
            service_el = port.find("service")

            if state_el is None:
                continue

            vulns = [
                s for s in port.findall("script")
                if "vuln" in s.attrib.get("id", "").lower()
            ]

            results.append({
                "target": target,
                "host": ip,
                "port": int(port.attrib.get("portid", 0)),
                "protocol": port.attrib.get("protocol", ""),
                "state": state_el.attrib.get("state", ""),
                "service": service_el.attrib.get("name", "") if service_el is not None else "",
                "product": service_el.attrib.get("product", "") if service_el is not None else "",
                "version": service_el.attrib.get("version", "") if service_el is not None else "",
                "vulnerabilities": len(vulns),
                "scan_profile": scan_profile
            })

    return results