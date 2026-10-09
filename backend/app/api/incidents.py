from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import Incident, IncidentEvent, AnalystNote, Alert, NormalizedEvent, User
from app.schemas.schemas import IncidentOut, IncidentCreate, IncidentUpdate, AnalystNoteOut, NoteCreate, AlertOut, NormalizedEventOut
from app.api.deps import get_current_user, log_audit_event

router = APIRouter(prefix="/incidents", tags=["Incidents & Timeline"])

@router.get("", response_model=List[IncidentOut])
def get_incidents(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    status: Optional[str] = None,
    severity: Optional[str] = None
):
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)
    
    incidents = query.order_by(Incident.created_at.desc()).all()
    
    # Enrich counts
    result = []
    for inc in incidents:
        inc_out = IncidentOut.model_validate(inc)
        alerts_count = db.query(IncidentEvent).filter(IncidentEvent.incident_id == inc.id, IncidentEvent.alert_id != None).count()
        events_count = db.query(IncidentEvent).filter(IncidentEvent.incident_id == inc.id, IncidentEvent.event_id != None).count()
        inc_out.alerts_count = alerts_count
        inc_out.events_count = events_count
        result.append(inc_out)
    return result

@router.post("", response_model=IncidentOut)
def create_incident(
    inc_in: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incident = Incident(
        title=inc_in.title,
        description=inc_in.description,
        severity=inc_in.severity,
        status="Open",
        created_by_id=current_user.id
    )
    db.add(incident)
    db.flush()

    if inc_in.alert_ids:
        for a_id in inc_in.alert_ids:
            assoc = IncidentEvent(incident_id=incident.id, alert_id=a_id)
            db.add(assoc)
            alert = db.query(Alert).filter(Alert.id == a_id).first()
            if alert:
                alert.status = "In Incident"

    db.commit()
    db.refresh(incident)

    log_audit_event(
        db, current_user, "INCIDENT_CREATED", target_type="Incident", target_id=incident.id,
        details=f"Created incident '{incident.title}' with severity {incident.severity}"
    )

    return IncidentOut.model_validate(incident)

@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident_detail(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    inc_out = IncidentOut.model_validate(incident)
    inc_out.alerts_count = db.query(IncidentEvent).filter(IncidentEvent.incident_id == incident.id, IncidentEvent.alert_id != None).count()
    inc_out.events_count = db.query(IncidentEvent).filter(IncidentEvent.incident_id == incident.id, IncidentEvent.event_id != None).count()
    
    notes_list = []
    for n in incident.notes:
        n_out = AnalystNoteOut.model_validate(n)
        n_out.analyst_username = n.analyst.username if n.analyst else "Analyst"
        notes_list.append(n_out)
    inc_out.notes = notes_list
    return inc_out

@router.put("/{incident_id}", response_model=IncidentOut)
def update_incident(
    incident_id: str,
    inc_update: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    old_status = incident.status
    if inc_update.title:
        incident.title = inc_update.title
    if inc_update.description:
        incident.description = inc_update.description
    if inc_update.status:
        incident.status = inc_update.status
    if inc_update.severity:
        incident.severity = inc_update.severity
    if inc_update.resolution_notes:
        incident.resolution_notes = inc_update.resolution_notes

    db.commit()
    db.refresh(incident)

    log_audit_event(
        db, current_user, "INCIDENT_UPDATED", target_type="Incident", target_id=incident.id,
        details=f"Updated incident status from '{old_status}' to '{incident.status}'"
    )

    inc_out = IncidentOut.model_validate(incident)
    return inc_out

@router.get("/{incident_id}/timeline")
def get_incident_timeline(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    assocs = db.query(IncidentEvent).filter(IncidentEvent.incident_id == incident_id).all()
    
    alerts_list = []
    events_list = []

    for assoc in assocs:
        if assoc.alert:
            alerts_list.append(AlertOut.model_validate(assoc.alert))
        if assoc.event:
            events_list.append(NormalizedEventOut.model_validate(assoc.event))

    return {
        "incident_id": incident_id,
        "title": incident.title,
        "status": incident.status,
        "alerts": alerts_list,
        "events": events_list
    }

@router.post("/{incident_id}/notes", response_model=AnalystNoteOut)
def add_analyst_note(
    incident_id: str,
    note_in: NoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    note = AnalystNote(
        incident_id=incident_id,
        analyst_id=current_user.id,
        content=note_in.content
    )
    db.add(note)
    db.commit()
    db.refresh(note)

    log_audit_event(
        db, current_user, "ANALYST_NOTE_ADDED", target_type="Incident", target_id=incident.id,
        details=f"Added investigation note to incident '{incident.title}'"
    )

    n_out = AnalystNoteOut.model_validate(note)
    n_out.analyst_username = current_user.username
    return n_out
