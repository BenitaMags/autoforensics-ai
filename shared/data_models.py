# ============================================================================
# shared/data_models.py
# Common data structures used across all agents
# ============================================================================

from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
from datetime import datetime


@dataclass
class IOC:
    """Indicator of Compromise"""
    type: str  # 'ip', 'domain', 'hash', 'url'
    value: str
    context: Dict[str, Any]
    score: float = 0.0
    passed_gate: bool = False
    enrichment: Optional[Dict] = None

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> 'IOC':
        return cls(**data)


@dataclass
class Attack:
    """Detected Attack"""
    type: str
    severity: str  # 'Critical', 'High', 'Medium', 'Low'
    confidence: str
    attacker_ips: List[str]
    timeline: List[Dict]
    mitre_techniques: List[str]
    description: str

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class CVE:
    """CVE Vulnerability"""
    id: str
    description: str
    severity: str
    cvss_score: float
    exploit_available: bool
    patch_available: bool
    affected_systems: List[str]
    mitre_mapping: List[str]

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class AnalysisSession:
    """Complete analysis session data"""
    session_id: str
    timestamp: str
    pcap_file: str
    log_file: str
    pcap_stats: Dict
    log_stats: Dict
    gating_stats: Dict
    attack: Attack
    cves: List[CVE]
    timeline: List[Dict]
    enriched_iocs: List[IOC]
    remediation: Dict
    dashboard_html: str
    analysis_time: float

    def to_dict(self) -> Dict:
        data = asdict(self)
        # Convert nested objects
        data['attack'] = self.attack.to_dict()
        data['cves'] = [cve.to_dict() for cve in self.cves]
        data['enriched_iocs'] = [ioc.to_dict() for ioc in self.enriched_iocs]
        return data
