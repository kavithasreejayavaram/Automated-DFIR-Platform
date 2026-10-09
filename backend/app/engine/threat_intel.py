import re
from datetime import datetime, timezone
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from app.db.models import IndicatorOfCompromise, NormalizedEvent
from app.core.config import settings

# Regex patterns for IOC extraction
IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
URL_PATTERN = re.compile(r'https?://[^\s/$.?#].[^\s]*')

DEFAULT_SYNTHETIC_IOCS = [
    {
        "ioc_value": "185.220.101.5",
        "ioc_type": "ip",
        "threat_level": "Critical",
        "description": "Known Tor exit node & brute-force scanner observed targeting SSH services.",
        "source": "Synthetic Threat Feed (Demo)",
        "is_synthetic": True
    },
    {
        "ioc_value": "194.26.29.114",
        "ioc_type": "ip",
        "threat_level": "High",
        "description": "Cobalt Strike C2 server infrastructure associated with credential harvesting.",
        "source": "Synthetic Threat Feed (Demo)",
        "is_synthetic": True
    },
    {
        "ioc_value": "45.147.229.177",
        "ioc_type": "ip",
        "threat_level": "High",
        "description": "Malicious scanner targeting RDP and VPN endpoints.",
        "source": "Synthetic Threat Feed (Demo)",
        "is_synthetic": True
    },
    {
        "ioc_value": "evil-exfil-domain.com",
        "ioc_type": "domain",
        "threat_level": "Critical",
        "description": "C2 exfiltration endpoint associated with ransomware campaigns.",
        "source": "Synthetic Threat Feed (Demo)",
        "is_synthetic": True
    },
    {
        "ioc_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "ioc_type": "file_hash",
        "threat_level": "High",
        "description": "Mimikatz LSASS password dumper executable hash.",
        "source": "Synthetic Threat Feed (Demo)",
        "is_synthetic": True
    }
]

def seed_synthetic_iocs(db: Session):
    for ioc_data in DEFAULT_SYNTHETIC_IOCS:
        existing = db.query(IndicatorOfCompromise).filter(
            IndicatorOfCompromise.ioc_value == ioc_data["ioc_value"]
        ).first()
        if not existing:
            ioc = IndicatorOfCompromise(**ioc_data)
            db.add(ioc)
    db.commit()

class ThreatIntelEngine:
    @staticmethod
    def extract_indicators_from_text(text: str) -> Dict[str, List[str]]:
        ips = list(set(IP_PATTERN.findall(text)))
        domains = list(set([d for d in DOMAIN_PATTERN.findall(text) if not IP_PATTERN.match(d) and not d.endswith(('.exe', '.dll', '.py', '.sh', '.json', '.csv', '.log'))]))
        hashes = list(set(SHA256_PATTERN.findall(text) + MD5_PATTERN.findall(text)))
        urls = list(set(URL_PATTERN.findall(text)))
        return {
            "ip": ips,
            "domain": domains,
            "file_hash": hashes,
            "url": urls
        }

    @staticmethod
    def match_events_against_iocs(db: Session, events: List[NormalizedEvent]) -> List[Dict[str, Any]]:
        seed_synthetic_iocs(db)
        
        all_iocs = db.query(IndicatorOfCompromise).all()
        ioc_map = {ioc.ioc_value.lower(): ioc for ioc in all_iocs}
        
        matches = []

        for ev in events:
            # Check source_ip & destination_ip
            for ip in [ev.source_ip, ev.destination_ip]:
                if ip and ip.lower() in ioc_map:
                    matched_ioc = ioc_map[ip.lower()]
                    matches.append({
                        "event_id": ev.id,
                        "timestamp": ev.timestamp,
                        "hostname": ev.hostname,
                        "username": ev.username,
                        "matched_value": ip,
                        "ioc_type": matched_ioc.ioc_type,
                        "threat_level": matched_ioc.threat_level,
                        "description": matched_ioc.description,
                        "source": matched_ioc.source,
                        "is_synthetic": matched_ioc.is_synthetic
                    })

            # Check raw record for hashes, domains, URLs
            extracted = ThreatIntelEngine.extract_indicators_from_text(ev.raw_record)
            for category, vals in extracted.items():
                for val in vals:
                    if val.lower() in ioc_map:
                        matched_ioc = ioc_map[val.lower()]
                        matches.append({
                            "event_id": ev.id,
                            "timestamp": ev.timestamp,
                            "hostname": ev.hostname,
                            "username": ev.username,
                            "matched_value": val,
                            "ioc_type": matched_ioc.ioc_type,
                            "threat_level": matched_ioc.threat_level,
                            "description": matched_ioc.description,
                            "source": matched_ioc.source,
                            "is_synthetic": matched_ioc.is_synthetic
                        })

        return matches

    @staticmethod
    def external_lookup(ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        if not settings.ENABLE_EXTERNAL_THREAT_INTEL:
            return {
                "ioc_value": ioc_value,
                "status": "disabled",
                "message": "External threat intelligence lookups are disabled by default. Configure ENABLE_EXTERNAL_THREAT_INTEL=true and VIRUSTOTAL_API_KEY to enable.",
                "reputation_score": None
            }
        
        # Safe mock response for external API lookup
        return {
            "ioc_value": ioc_value,
            "status": "success",
            "provider": "VirusTotal (Mock Integration)",
            "malicious_votes": 12,
            "harmless_votes": 45,
            "reputation_score": -35,
            "categories": ["malware_distribution", "scanner"]
        }
