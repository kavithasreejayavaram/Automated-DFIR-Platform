import os
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, Response
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import EvidenceFile, NormalizedEvent, User
from app.schemas.schemas import NormalizedEventOut, EvidenceFileOut
from app.engine.ingestion import LogIngestionEngine
from app.engine.detection import DetectionEngine
from app.engine.correlator import IncidentCorrelatorEngine
from app.engine.threat_intel import ThreatIntelEngine
from app.core.config import settings
from app.api.deps import get_current_user, log_audit_event

router = APIRouter(prefix="/logs", tags=["Log Ingestion & Normalization"])

def ensure_storage_dir():
    os.makedirs(settings.EVIDENCE_STORAGE_DIR, exist_ok=True)

@router.post("/upload", response_model=EvidenceFileOut)
async def upload_and_ingest_log_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    ensure_storage_dir()
    
    content = await file.read()
    if len(content) > 25 * 1024 * 1024:  # 25MB max size
        raise HTTPException(status_code=400, detail="File size exceeds maximum threshold of 25MB.")
    
    try:
        normalized_records, sha256_hash, line_count = LogIngestionEngine.process_file_content(content, file.filename)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Log normalization failed: {str(e)}")

    # Check duplicate hash or save
    save_path = os.path.join(settings.EVIDENCE_STORAGE_DIR, f"{sha256_hash}_{file.filename}")
    with open(save_path, "wb") as f:
        f.write(content)

    evidence_file = EvidenceFile(
        filename=file.filename,
        file_path=save_path,
        file_size=len(content),
        sha256_hash=sha256_hash,
        line_count=line_count,
        analyst_id=current_user.id,
        is_verified=True
    )
    db.add(evidence_file)
    db.flush()

    # Store normalized events
    db_events = []
    for rec in normalized_records:
        ev = NormalizedEvent(
            evidence_file_id=evidence_file.id,
            timestamp=rec["timestamp"],
            hostname=rec["hostname"],
            username=rec["username"],
            source_ip=rec["source_ip"],
            destination_ip=rec["destination_ip"],
            event_type=rec["event_type"],
            event_description=rec["event_description"],
            process_name=rec["process_name"],
            auth_result=rec["auth_result"],
            raw_record=rec["raw_record"],
            event_hash=rec.get("event_hash")
        )
        db.add(ev)
        db_events.append(ev)

    db.commit()
    db.refresh(evidence_file)

    # Automatically trigger detection engine & correlation
    alerts = DetectionEngine.run_rules_on_events(db, db_events, evidence_file.id)
    incidents = IncidentCorrelatorEngine.correlate_alerts_into_incidents(db, alerts)
    ThreatIntelEngine.match_events_against_iocs(db, db_events)

    log_audit_event(
        db, current_user, "EVIDENCE_UPLOAD", target_type="EvidenceFile", target_id=evidence_file.id,
        details=f"Uploaded '{file.filename}' (SHA256: {sha256_hash[:12]}...). Ingested {len(db_events)} events, generated {len(alerts)} alert(s) and {len(incidents)} incident(s)."
    )

    return evidence_file

@router.post("/synthetic/ingest/{scenario}", response_model=EvidenceFileOut)
def ingest_synthetic_scenario(
    scenario: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scenario_files = {
        "brute_force": ("brute_force_attack.csv", "backend/datasets/brute_force_attack.csv"),
        "suspicious_process": ("suspicious_process_exec.jsonl", "backend/datasets/suspicious_process_exec.jsonl"),
        "privilege_escalation": ("privilege_escalation.csv", "backend/datasets/privilege_escalation.csv"),
        "benign_noise": ("benign_corporate_noise.json", "backend/datasets/benign_corporate_noise.json")
    }

    if scenario not in scenario_files:
        raise HTTPException(status_code=400, detail=f"Unknown scenario '{scenario}'. Options: {list(scenario_files.keys())}")

    filename, file_path = scenario_files[scenario]
    if not os.path.exists(file_path):
        # Try relative to current working directory
        file_path = os.path.join("datasets", filename)
        if not os.path.exists(file_path):
            raise HTTPException(status_code=444, detail=f"Synthetic dataset file {filename} not found.")

    with open(file_path, "rb") as f:
        content = f.read()

    normalized_records, sha256_hash, line_count = LogIngestionEngine.process_file_content(content, filename)
    save_path = os.path.join(settings.EVIDENCE_STORAGE_DIR, f"{sha256_hash}_{filename}")
    os.makedirs(settings.EVIDENCE_STORAGE_DIR, exist_ok=True)
    with open(save_path, "wb") as f:
        f.write(content)

    evidence_file = EvidenceFile(
        filename=f"Synthetic_{filename}",
        file_path=save_path,
        file_size=len(content),
        sha256_hash=sha256_hash,
        line_count=line_count,
        analyst_id=current_user.id,
        is_verified=True
    )
    db.add(evidence_file)
    db.flush()

    db_events = []
    for rec in normalized_records:
        ev = NormalizedEvent(
            evidence_file_id=evidence_file.id,
            timestamp=rec["timestamp"],
            hostname=rec["hostname"],
            username=rec["username"],
            source_ip=rec["source_ip"],
            destination_ip=rec["destination_ip"],
            event_type=rec["event_type"],
            event_description=rec["event_description"],
            process_name=rec["process_name"],
            auth_result=rec["auth_result"],
            raw_record=rec["raw_record"],
            event_hash=rec.get("event_hash")
        )
        db.add(ev)
        db_events.append(ev)

    db.commit()
    db.refresh(evidence_file)

    alerts = DetectionEngine.run_rules_on_events(db, db_events, evidence_file.id)
    IncidentCorrelatorEngine.correlate_alerts_into_incidents(db, alerts)
    ThreatIntelEngine.match_events_against_iocs(db, db_events)

    log_audit_event(
        db, current_user, "SYNTHETIC_DATASET_INGEST", target_type="EvidenceFile", target_id=evidence_file.id,
        details=f"Ingested synthetic dataset '{scenario}'. Ingested {len(db_events)} events, generated {len(alerts)} alerts."
    )

    return evidence_file

@router.get("/events", response_model=List[NormalizedEventOut])
def get_normalized_events(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = Query(100, le=1000),
    offset: int = 0,
    search: Optional[str] = None,
    hostname: Optional[str] = None,
    username: Optional[str] = None,
    event_type: Optional[str] = None,
    auth_result: Optional[str] = None
):
    query = db.query(NormalizedEvent)

    if hostname:
        query = query.filter(NormalizedEvent.hostname.ilike(f"%{hostname}%"))
    if username:
        query = query.filter(NormalizedEvent.username.ilike(f"%{username}%"))
    if event_type:
        query = query.filter(NormalizedEvent.event_type.ilike(f"%{event_type}%"))
    if auth_result:
        query = query.filter(NormalizedEvent.auth_result == auth_result.upper())
    if search:
        query = query.filter(
            (NormalizedEvent.event_description.ilike(f"%{search}%")) |
            (NormalizedEvent.raw_record.ilike(f"%{search}%")) |
            (NormalizedEvent.process_name.ilike(f"%{search}%"))
        )

    return query.order_by(NormalizedEvent.timestamp.desc()).offset(offset).limit(limit).all()

@router.get("/synthetic/download/{scenario}")
def download_synthetic_dataset(scenario: str):
    scenario_files = {
        "brute_force": ("brute_force_attack.csv", "backend/datasets/brute_force_attack.csv"),
        "suspicious_process": ("suspicious_process_exec.jsonl", "backend/datasets/suspicious_process_exec.jsonl"),
        "privilege_escalation": ("privilege_escalation.csv", "backend/datasets/privilege_escalation.csv"),
        "benign_noise": ("benign_corporate_noise.json", "backend/datasets/benign_corporate_noise.json")
    }
    if scenario not in scenario_files:
        raise HTTPException(status_code=404, detail="Dataset scenario not found")
    
    filename, path = scenario_files[scenario]
    if not os.path.exists(path):
        path = os.path.join("datasets", filename)

    return FileResponse(path=path, filename=filename, media_type="application/octet-stream")
