# Pydantic models

from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


# =================================================
# COMMON / BASE SCHEMAS
# =================================================

class APIStatus(BaseModel):
    status: str
    message: Optional[str] = None
    timestamp: Optional[str] = None


# =================================================
# SCAN REQUEST (Dashboard → Backend)
# =================================================

class ScanFilters(BaseModel):
    cidr: Optional[str] = None
    asn: Optional[str] = None
    organization: Optional[str] = None


class ScanRequest(BaseModel):
    """
    Scan request sent from dashboard.

    At least ONE of:
    - targets
    - ports
    - uploaded file (handled separately)

    must be provided.
    """
    targets: Optional[List[str]] = Field(default_factory=list)
    ports: Optional[str] = None
    scan_profile: str = Field(default="Normal", pattern="^(Quick|Normal|High)$")
    scan_type: str = Field(default="nmap")
    filters: Optional[ScanFilters] = None


class ScanStartResponse(BaseModel):
    status: str
    targets: List[str]
    scan_id: Optional[str] = None


# =================================================
# LAYER 1 — NMAP RESULTS
# =================================================

class NmapService(BaseModel):
    port: int
    protocol: str
    state: str
    service: Optional[str] = ""
    product: Optional[str] = ""
    version: Optional[str] = ""
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)


class NmapHost(BaseModel):
    host: str
    hostname: Optional[str] = ""
    services: List[NmapService] = Field(default_factory=list)


class NmapResult(BaseModel):
    target: str
    scan_profile: str
    data: Dict[str, NmapHost]


# =================================================
# LAYER 2 — THREAT INTELLIGENCE
# =================================================

class ThreatIntelItem(BaseModel):
    source: str                 # VirusTotal / Shodan / Vulners / NVD
    indicator: str              # IP / hash / CVE / domain
    severity: Optional[str] = None
    confidence: Optional[float] = None
    details: Optional[Dict[str, Any]] = None
    timestamp: Optional[str] = None


class ThreatIntelResponse(BaseModel):
    count: int
    data: List[ThreatIntelItem]


# =================================================
# LAYER 3 — RISK SCORING
# =================================================

class RiskAsset(BaseModel):
    host: str
    risk_score: float
    risk_level: str             # Low / Medium / High / Critical
    threat_score: Optional[float] = None
    exposed_services: Optional[int] = None
    notes: Optional[str] = None


class RiskSummary(BaseModel):
    total_assets: int
    critical: int
    high: int
    medium: int
    low: int
    generated_at: Optional[str] = None


# =================================================
# FULL PIPELINE RESULT (DB STORAGE)
# =================================================

class ScanRecord(BaseModel):
    scan_type: str
    scan_profile: str
    targets: List[str]
    ports: Optional[str]
    created_at: Optional[str] = Field(
        default_factory=lambda: datetime.utcnow().isoformat()
    )

    layer1: Optional[Dict[str, Any]] = None
    layer2: Optional[Dict[str, Any]] = None
    layer3: Optional[Dict[str, Any]] = None


# =================================================
# SCAN STATUS (NON-BLOCKING)
# =================================================

class ScanStatus(BaseModel):
    state: str                  # idle | running | completed | failed
    started_at: Optional[str]
    finished_at: Optional[str]


# =================================================
# ALERTS
# =================================================

class Alert(BaseModel):
    alert_type: str
    severity: str               # Low / Medium / High / Critical
    title: str
    description: Optional[str]
    target: Optional[str]
    created_at: Optional[str]
    acknowledged: bool = False


class AlertSummary(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int


# =================================================
# REPORTING
# =================================================

class ReportMetadata(BaseModel):
    scan_type: str
    scan_profile: str
    scan_time: str
    generated_at: str


class ReportResponse(BaseModel):
    metadata: ReportMetadata
    summary: RiskSummary
    download_links: Dict[str, str]  # pdf / csv / excel
