from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from datetime import datetime
from typing import Dict, Any, Optional


# =================================================
# CORE PDF GENERATOR
# =================================================
def generate_executive_pdf(
    summary: Dict[str, Any],
    path: Optional[str] = None
) -> str:
    """
    Generate an executive-level cyber risk PDF report.

    Parameters
    ----------
    summary : dict
        Expected keys (safe if missing):
        - scan_type
        - scan_time
        - hosts
        - findings / vulns
        - risk_level
        - threat_score
        - module (optional)

    path : str
        Output PDF path

    Returns
    -------
    str : path to generated PDF
    """

    if not path:
        path = "executive_report.pdf"

    # ---------------- Styles ----------------
    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    h_style = styles["Heading2"]
    p_style = styles["BodyText"]

    # ---------------- Document ----------------
    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )

    elements = []

    # =================================================
    # TITLE
    # =================================================
    elements.append(Paragraph("Cyber Risk Assessment Report", title_style))
    elements.append(Spacer(1, 16))

    # =================================================
    # META INFO
    # =================================================
    elements.append(Paragraph("Executive Summary", h_style))
    elements.append(Spacer(1, 10))

    scan_type = summary.get("scan_type", "Nmap")
    scan_time = summary.get("scan_time", datetime.utcnow().isoformat())
    module = summary.get("module", "Overview")

    elements.append(
        Paragraph(
            f"""
            <b>Module:</b> {module}<br/>
            <b>Scan Type:</b> {scan_type}<br/>
            <b>Generated At:</b> {scan_time}
            """,
            p_style,
        )
    )

    elements.append(Spacer(1, 14))

    # =================================================
    # METRICS TABLE
    # =================================================
    hosts = summary.get("hosts", summary.get("assets", 0))
    findings = summary.get("findings", summary.get("vulns", 0))
    risk_level = summary.get("risk_level", "Unknown")
    threat_score = summary.get("threat_score", 0)

    table_data = [
        ["Metric", "Value"],
        ["Total Hosts", str(hosts)],
        ["Total Findings", str(findings)],
        ["Risk Level", str(risk_level)],
        ["Threat Score", str(threat_score)],
    ]

    table = Table(table_data, hAlign="LEFT", colWidths=[200, 200])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("ALIGN", (1, 1), (-1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONT", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
            ]
        )
    )

    elements.append(table)
    elements.append(Spacer(1, 20))

    # =================================================
    # RISK INTERPRETATION
    # =================================================
    elements.append(Paragraph("Risk Interpretation", h_style))
    elements.append(Spacer(1, 8))

    interpretation = _interpret_risk(risk_level, threat_score)
    elements.append(Paragraph(interpretation, p_style))

    elements.append(Spacer(1, 18))

    # =================================================
    # RECOMMENDATIONS
    # =================================================
    elements.append(Paragraph("Key Recommendations", h_style))
    elements.append(Spacer(1, 8))

    for rec in _recommendations(risk_level):
        elements.append(Paragraph(f"- {rec}", p_style))
        elements.append(Spacer(1, 4))

    # =================================================
    # FOOTER
    # =================================================
    elements.append(Spacer(1, 24))
    elements.append(
        Paragraph(
            "<i>This report is generated automatically and is suitable for audit, "
            "compliance, and management review.</i>",
            styles["Italic"],
        )
    )

    # ---------------- Build PDF ----------------
    doc.build(elements)

    return path


# =================================================
# HELPER FUNCTIONS
# =================================================
def _interpret_risk(level: str, score: int) -> str:
    if level == "Critical":
        return (
            f"The organization is currently exposed to <b>CRITICAL</b> risk "
            f"(Threat Score: {score}). Immediate remediation is required."
        )
    if level == "High":
        return (
            f"The organization has a <b>HIGH</b> risk posture. "
            f"Prioritize remediation of exposed services."
        )
    if level == "Medium":
        return (
            "The organization shows a <b>MODERATE</b> risk level. "
            "Risk reduction actions are recommended."
        )
    return (
        "The organization currently shows a <b>LOW</b> risk posture. "
        "Maintain security hygiene and monitoring."
    )


def _recommendations(level: str):
    base = [
        "Restrict access to unnecessary open ports.",
        "Apply the latest security patches.",
        "Continuously monitor exposed services.",
    ]

    if level in ("Critical", "High"):
        base.extend(
            [
                "Immediately isolate high-risk hosts.",
                "Perform a detailed incident investigation.",
                "Enable real-time alerting and logging.",
            ]
        )

    return base
