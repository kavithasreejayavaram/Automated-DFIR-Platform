from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.db.database import get_db
from app.db.models import NormalizedEvent, EvidenceFile, Alert, Incident, User
from app.schemas.schemas import DashboardAnalytics, AlertOut, EvidenceFileOut
from app.api.deps import get_current_user

router = APIRouter(prefix="/analytics", tags=["Dashboard & Analytics"])

@router.get("/dashboard", response_model=DashboardAnalytics)
def get_dashboard_analytics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    total_events = db.query(NormalizedEvent).count()
    total_evidence_files = db.query(EvidenceFile).count()
    total_alerts = db.query(Alert).count()
    active_incidents = db.query(Incident).filter(Incident.status.in_(["Open", "Investigating"])).count()

    # Severity distribution
    sev_counts = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    alerts_by_severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for sev, count in sev_counts:
        if sev in alerts_by_severity:
            alerts_by_severity[sev] = count

    # Incident status distribution
    stat_counts = db.query(Incident.status, func.count(Incident.id)).group_by(Incident.status).all()
    incidents_by_status = {"Open": 0, "Investigating": 0, "Resolved": 0, "False Positive": 0}
    for stat, count in stat_counts:
        if stat in incidents_by_status:
            incidents_by_status[stat] = count

    # Top affected hosts
    top_hosts_q = db.query(
        NormalizedEvent.hostname, func.count(NormalizedEvent.id).label('count')
    ).filter(NormalizedEvent.hostname != None).group_by(NormalizedEvent.hostname).order_by(func.count(NormalizedEvent.id).desc()).limit(5).all()
    top_hosts = [{"hostname": h, "event_count": c} for h, c in top_hosts_q]

    # Top affected users
    top_users_q = db.query(
        NormalizedEvent.username, func.count(NormalizedEvent.id).label('count')
    ).filter(NormalizedEvent.username != None, NormalizedEvent.username != 'UNKNOWN_USER').group_by(NormalizedEvent.username).order_by(func.count(NormalizedEvent.id).desc()).limit(5).all()
    top_users = [{"username": u, "event_count": c} for u, c in top_users_q]

    # Timeline trend (group events by hour/day)
    events_by_date_q = db.query(
        func.strftime('%Y-%m-%d %H:00', NormalizedEvent.timestamp).label('hour'),
        func.count(NormalizedEvent.id).label('count')
    ).group_by('hour').order_by('hour').limit(24).all()
    event_timeline = [{"time": time_str or "N/A", "count": count} for time_str, count in events_by_date_q]

    # Recent alerts & evidence
    recent_alerts_db = db.query(Alert).order_by(Alert.timestamp.desc()).limit(5).all()
    recent_evidence_db = db.query(EvidenceFile).order_by(EvidenceFile.acquisition_time.desc()).limit(5).all()

    recent_alerts = [AlertOut.model_validate(a) for a in recent_alerts_db]
    recent_evidence = [EvidenceFileOut.model_validate(e) for e in recent_evidence_db]

    return DashboardAnalytics(
        total_events=total_events,
        total_evidence_files=total_evidence_files,
        total_alerts=total_alerts,
        active_incidents=active_incidents,
        alerts_by_severity=alerts_by_severity,
        incidents_by_status=incidents_by_status,
        top_affected_hosts=top_hosts,
        top_affected_users=top_users,
        event_timeline=event_timeline,
        recent_alerts=recent_alerts,
        recent_evidence=recent_evidence
    )
