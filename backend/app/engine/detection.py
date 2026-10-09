from datetime import timedelta
import json
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from app.db.models import NormalizedEvent, DetectionRule, Alert

# Seed default detection rules if not existing
DEFAULT_RULES = [
    {
        "rule_code": "RULE-001",
        "name": "Repeated Failed Authentication (Brute Force)",
        "description": "Detects 3 or more failed authentication attempts for the same username or source IP within a sliding 15-minute window.",
        "severity": "High",
        "confidence": "High",
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force",
        "query_logic": "count(auth_result == 'FAILURE') >= 3 within 15 mins by user or source_ip",
        "remediation_steps": "Lock affected account, verify IP location, check if MFA was prompted, inspect endpoint for automated credential stuffing scripts.",
        "enabled": True
    },
    {
        "rule_code": "RULE-002",
        "name": "Successful Authentication Post Repeated Failures",
        "description": "Detects a successful authentication event following multiple prior failed login attempts for the same account.",
        "severity": "Critical",
        "confidence": "High",
        "mitre_technique_id": "T1078",
        "mitre_technique_name": "Valid Accounts",
        "query_logic": "auth_result == 'SUCCESS' following >= 2 auth_result == 'FAILURE' within 30 mins",
        "remediation_steps": "Immediately verify with user if login was legitimate. Force password reset, revoke active session tokens, audit post-login activity.",
        "enabled": True
    },
    {
        "rule_code": "RULE-003",
        "name": "Suspicious Process Command Execution",
        "description": "Detects execution of processes associated with credential dumping, encoded execution, or administrative utility misuse (e.g. mimikatz, powershell -enc, certutil, whoami /priv).",
        "severity": "High",
        "confidence": "Medium",
        "mitre_technique_id": "T1059",
        "mitre_technique_name": "Command and Scripting Interpreter",
        "query_logic": "process_name matches [mimikatz, certutil, powershell -enc, cmd.exe /c, whoami /priv]",
        "remediation_steps": "Isolate the host, terminate the parent process, collect memory dump, check for persistent scheduled tasks or secondary payloads.",
        "enabled": True
    },
    {
        "rule_code": "RULE-004",
        "name": "Unusual Privilege Change / Escalation",
        "description": "Detects modifications to local/domain administrative groups, sudo privileges, or unexpected user privilege grants.",
        "severity": "High",
        "confidence": "High",
        "mitre_technique_id": "T1098",
        "mitre_technique_name": "Account Manipulation",
        "query_logic": "event_type in [PRIVILEGE_CHANGE, GROUP_ADDED, 4728, 4732, sudo] or event_description contains 'added to group'",
        "remediation_steps": "Verify change authorization via ticket system. Revert unauthorized privilege additions, audit administrative action logs.",
        "enabled": True
    },
    {
        "rule_code": "RULE-005",
        "name": "Potential Audit Log Tampering / Clearing",
        "description": "Detects execution of commands or system events indicating security log clearing or event logging service stoppage.",
        "severity": "Critical",
        "confidence": "High",
        "mitre_technique_id": "T1070",
        "mitre_technique_name": "Indicator Removal: Clear Windows Event Logs",
        "query_logic": "event_type in [LOG_CLEARED, 1102, 4719] or process_name/description contains 'wevtutil cl' or 'rm -rf /var/log'",
        "remediation_steps": "Escalate to Tier 3 incident handler immediately. Collect SIEM external forwarder logs, check endpoint shadow copies.",
        "enabled": True
    },
    {
        "rule_code": "RULE-006",
        "name": "Login Activity from Suspicious External IP",
        "description": "Detects authentication attempts originating from anomalous external IP addresses outside typical corporate baselines.",
        "severity": "Medium",
        "confidence": "Medium",
        "mitre_technique_id": "T1078.004",
        "mitre_technique_name": "Valid Accounts: Cloud Accounts",
        "query_logic": "source_ip in threat intelligence feed or external untrusted subnet",
        "remediation_steps": "Verify user geographical location, check VPN logs, block offending IP at gateway firewall.",
        "enabled": True
    }
]

def seed_detection_rules(db: Session):
    for r_data in DEFAULT_RULES:
        existing = db.query(DetectionRule).filter(DetectionRule.rule_code == r_data["rule_code"]).first()
        if not existing:
            rule = DetectionRule(**r_data)
            db.add(rule)
    db.commit()

class DetectionEngine:
    @staticmethod
    def run_rules_on_events(db: Session, events: List[NormalizedEvent], file_id: str = None) -> List[Alert]:
        seed_detection_rules(db)
        rules_map = {r.rule_code: r for r in db.query(DetectionRule).filter(DetectionRule.enabled == True).all()}
        
        alerts_created = []

        # Group events by user & host for stateful rules
        user_events: Dict[str, List[NormalizedEvent]] = {}
        host_events: Dict[str, List[NormalizedEvent]] = {}

        for ev in sorted(events, key=lambda x: x.timestamp):
            if ev.username:
                user_events.setdefault(ev.username, []).append(ev)
            if ev.hostname:
                host_events.setdefault(ev.hostname, []).append(ev)

        # 1. Stateless Rules (RULE-003, RULE-004, RULE-005, RULE-006)
        for ev in events:
            proc = (ev.process_name or "").lower()
            desc = (ev.event_description or "").lower()
            etype = (ev.event_type or "").upper()
            src_ip = ev.source_ip or ""

            # RULE-003: Suspicious Process Execution
            if "RULE-003" in rules_map:
                rule = rules_map["RULE-003"]
                suspicious_patterns = ["mimikatz", "certutil", "powershell -enc", "powershell.exe -e", "cmd /c", "whoami /priv", "vssadmin delete"]
                if any(pat in proc or pat in desc for pat in suspicious_patterns):
                    alert = Alert(
                        rule_id=rule.id,
                        evidence_file_id=file_id or ev.evidence_file_id,
                        timestamp=ev.timestamp,
                        hostname=ev.hostname,
                        username=ev.username,
                        source_ip=ev.source_ip,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        trigger_reason=f"Suspicious process or command execution detected: {ev.process_name or ev.event_description}",
                        trigger_events_json=json.dumps([ev.id]),
                        recommended_actions=rule.remediation_steps,
                        status="New"
                    )
                    db.add(alert)
                    alerts_created.append(alert)

            # RULE-004: Privilege Change
            if "RULE-004" in rules_map:
                rule = rules_map["RULE-004"]
                if etype in ["PRIVILEGE_CHANGE", "GROUP_ADDED", "4728", "4732", "SUDO"] or "added to group" in desc or "privilege" in desc or "sudo:" in desc:
                    alert = Alert(
                        rule_id=rule.id,
                        evidence_file_id=file_id or ev.evidence_file_id,
                        timestamp=ev.timestamp,
                        hostname=ev.hostname,
                        username=ev.username,
                        source_ip=ev.source_ip,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        trigger_reason=f"Account privilege modification or elevated permission event observed: {ev.event_description}",
                        trigger_events_json=json.dumps([ev.id]),
                        recommended_actions=rule.remediation_steps,
                        status="New"
                    )
                    db.add(alert)
                    alerts_created.append(alert)

            # RULE-005: Log Tampering / Clearing
            if "RULE-005" in rules_map:
                rule = rules_map["RULE-005"]
                if etype in ["LOG_CLEARED", "1102", "4719"] or "wevtutil" in proc or "wevtutil" in desc or "cleared" in desc or "rm -rf /var/log" in desc:
                    alert = Alert(
                        rule_id=rule.id,
                        evidence_file_id=file_id or ev.evidence_file_id,
                        timestamp=ev.timestamp,
                        hostname=ev.hostname,
                        username=ev.username,
                        source_ip=ev.source_ip,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        trigger_reason=f"Security event log clearing or audit tampering detected: {ev.event_description}",
                        trigger_events_json=json.dumps([ev.id]),
                        recommended_actions=rule.remediation_steps,
                        status="New"
                    )
                    db.add(alert)
                    alerts_created.append(alert)

            # RULE-006: Unusual IP Login
            if "RULE-006" in rules_map:
                rule = rules_map["RULE-006"]
                if src_ip and (src_ip.startswith("185.") or src_ip.startswith("194.") or src_ip.startswith("45.") or "unusual_ip" in desc):
                    alert = Alert(
                        rule_id=rule.id,
                        evidence_file_id=file_id or ev.evidence_file_id,
                        timestamp=ev.timestamp,
                        hostname=ev.hostname,
                        username=ev.username,
                        source_ip=ev.source_ip,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        trigger_reason=f"Authentication observed from anomalous IP address: {src_ip}",
                        trigger_events_json=json.dumps([ev.id]),
                        recommended_actions=rule.remediation_steps,
                        status="New"
                    )
                    db.add(alert)
                    alerts_created.append(alert)

        # 2. Stateful Rules (RULE-001, RULE-002)
        if "RULE-001" in rules_map or "RULE-002" in rules_map:
            rule_001 = rules_map.get("RULE-001")
            rule_002 = rules_map.get("RULE-002")

            for username, u_events in user_events.items():
                if username == "UNKNOWN_USER":
                    continue
                failed_window: List[NormalizedEvent] = []
                for ev in u_events:
                    if ev.auth_result == "FAILURE":
                        failed_window.append(ev)
                        # Keep only events within 15 minutes window
                        failed_window = [e for e in failed_window if ev.timestamp - e.timestamp <= timedelta(minutes=15)]
                        
                        if rule_001 and len(failed_window) == 3:
                            alert = Alert(
                                rule_id=rule_001.id,
                                evidence_file_id=file_id or ev.evidence_file_id,
                                timestamp=ev.timestamp,
                                hostname=ev.hostname,
                                username=ev.username,
                                source_ip=ev.source_ip,
                                severity=rule_001.severity,
                                confidence=rule_001.confidence,
                                trigger_reason=f"Multiple failed authentication attempts ({len(failed_window)}) for user '{username}' within 15 minutes.",
                                trigger_events_json=json.dumps([e.id for e in failed_window]),
                                recommended_actions=rule_001.remediation_steps,
                                status="New"
                            )
                            db.add(alert)
                            alerts_created.append(alert)
                    elif ev.auth_result == "SUCCESS":
                        if rule_002 and len(failed_window) >= 2:
                            alert = Alert(
                                rule_id=rule_002.id,
                                evidence_file_id=file_id or ev.evidence_file_id,
                                timestamp=ev.timestamp,
                                hostname=ev.hostname,
                                username=ev.username,
                                source_ip=ev.source_ip,
                                severity=rule_002.severity,
                                confidence=rule_002.confidence,
                                trigger_reason=f"Successful login for user '{username}' following {len(failed_window)} recent authentication failures.",
                                trigger_events_json=json.dumps([e.id for e in failed_window] + [ev.id]),
                                recommended_actions=rule_002.remediation_steps,
                                status="New"
                            )
                            db.add(alert)
                            alerts_created.append(alert)
                        # Reset window after success
                        failed_window = []

        db.commit()
        return alerts_created
