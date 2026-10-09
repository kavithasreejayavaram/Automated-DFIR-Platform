import os
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import Report, Incident, User
from app.schemas.schemas import ReportOut
from app.reports.generator import ReportGenerator
from app.api.deps import get_current_user, log_audit_event
from app.core.config import settings

router = APIRouter(prefix="/reports", tags=["Investigation Reports"])

@router.post("/generate/{incident_id}", response_model=ReportOut)
def generate_reports_for_incident(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    try:
        pdf_path, json_path = ReportGenerator.generate_incident_report(db, incident_id, current_user.username)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")

    pdf_report = Report(
        incident_id=incident.id,
        generated_by_id=current_user.id,
        report_title=f"Incident Report: {incident.title}",
        file_path=pdf_path,
        file_format="PDF"
    )
    db.add(pdf_report)
    db.commit()
    db.refresh(pdf_report)

    log_audit_event(
        db, current_user, "REPORT_GENERATED", target_type="Incident", target_id=incident.id,
        details=f"Generated PDF and JSON reports for incident '{incident.title}'"
    )

    return pdf_report

@router.get("", response_model=List[ReportOut])
def get_reports(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(Report).order_by(Report.created_at.desc()).all()

@router.get("/download/{filename}")
def download_report_file(
    filename: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    file_path = os.path.join(settings.REPORT_STORAGE_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Requested report file not found on disk.")

    media_type = "application/pdf" if filename.endswith(".pdf") else "application/json"
    log_audit_event(
        db, current_user, "REPORT_DOWNLOADED", target_type="Report", details=f"Downloaded report file '{filename}'"
    )
    return FileResponse(path=file_path, filename=filename, media_type=media_type)
