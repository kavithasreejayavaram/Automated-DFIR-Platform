from datetime import datetime, timezone
import json
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from app.db.models import Alert, Incident, IncidentEvent, NormalizedEvent

class IncidentCorrelatorEngine:
    @staticmethod
    def correlate_alerts_into_incidents(db: Session, alerts: List[Alert]) -> List[Incident]:
        if not alerts:
            return []

        # Group alerts by entity (username, hostname, source_ip)
        grouped_alerts: Dict[str, List[Alert]] = {}

        for alert in alerts:
            key = f"{alert.username or 'NO_USER'}|{alert.hostname or 'NO_HOST'}|{alert.source_ip or 'NO_IP'}"
            grouped_alerts.setdefault(key, []).append(alert)

        created_incidents = []

        for key, group in grouped_alerts.items():
            user, host, ip = key.split('|')
            entity_label = f"User '{user}'" if user != 'NO_USER' else (f"Host '{host}'" if host != 'NO_HOST' else f"IP '{ip}'")
            
            # Determine maximum severity
            severities = [a.severity for a in group]
            highest_severity = "Critical" if "Critical" in severities else ("High" if "High" in severities else ("Medium" if "Medium" in severities else "Low"))

            # Check if an open incident already exists for this entity within last 24h
            existing_incident = db.query(Incident).filter(
                Incident.status.in_(["Open", "Investigating"]),
                Incident.title.contains(entity_label)
            ).order_by(Incident.created_at.desc()).first()

            if existing_incident:
                incident = existing_incident
                # Upgrade severity if higher
                if highest_severity == "Critical" or (highest_severity == "High" and incident.severity not in ["Critical", "High"]):
                    incident.severity = highest_severity
                incident.updated_at = datetime.now(timezone.utc)
            else:
                title = f"Security Incident: Suspicious Activity Detected on {entity_label}"
                desc = f"Auto-correlated incident derived from {len(group)} alert(s) involving entity {entity_label}. Alerts include: " + ", ".join(list(set([a.rule.name if a.rule else 'Rule Alert' for a in group])))
                
                incident = Incident(
                    title=title,
                    description=desc,
                    severity=highest_severity,
                    status="Open"
                )
                db.add(incident)
                db.flush()  # populate incident.id
                created_incidents.append(incident)

            # Associate alerts and their underlying events
            for alert in group:
                alert.status = "In Incident"
                
                # Check if association already exists
                existing_assoc = db.query(IncidentEvent).filter(
                    IncidentEvent.incident_id == incident.id,
                    IncidentEvent.alert_id == alert.id
                ).first()

                if not existing_assoc:
                    assoc = IncidentEvent(
                        incident_id=incident.id,
                        alert_id=alert.id
                    )
                    db.add(assoc)

                # Connect underlying normalized events
                if alert.trigger_events_json:
                    try:
                        ev_ids = json.loads(alert.trigger_events_json)
                        for ev_id in ev_ids:
                            existing_ev_assoc = db.query(IncidentEvent).filter(
                                IncidentEvent.incident_id == incident.id,
                                IncidentEvent.event_id == ev_id
                            ).first()
                            if not existing_ev_assoc:
                                ev_assoc = IncidentEvent(
                                    incident_id=incident.id,
                                    event_id=ev_id
                                )
                                db.add(ev_assoc)
                    except Exception:
                        pass

        db.commit()
        return created_incidents
