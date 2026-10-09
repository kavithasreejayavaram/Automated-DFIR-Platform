import os
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import EvidenceFile, User
from app.schemas.schemas import EvidenceFileOut
from app.engine.ingestion import compute_sha256
from app.api.deps import get_current_user, log_audit_event

router = APIRouter(prefix="/evidence", tags=["Evidence Vault & Integrity"])

@router.get("", response_model=List[EvidenceFileOut])
def get_evidence_files(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(EvidenceFile).order_by(EvidenceFile.acquisition_time.desc()).all()

@router.post("/{evidence_id}/verify")
def verify_evidence_integrity(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    evidence = db.query(EvidenceFile).filter(EvidenceFile.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence file record not found")

    if not os.path.exists(evidence.file_path):
        evidence.is_verified = False
        db.commit()
        log_audit_event(
            db, current_user, "EVIDENCE_VERIFY_FAILED", target_type="EvidenceFile", target_id=evidence.id,
            details=f"File missing on disk at path '{evidence.file_path}'"
        )
        return {
            "evidence_id": evidence.id,
            "filename": evidence.filename,
            "recorded_hash": evidence.sha256_hash,
            "current_hash": None,
            "status": "FILE_MISSING",
            "is_verified": False,
            "message": "CRITICAL ERROR: Original evidence file does not exist on disk."
        }

    with open(evidence.file_path, "rb") as f:
        content = f.read()

    current_hash = compute_sha256(content)
    is_match = (current_hash == evidence.sha256_hash)
    evidence.is_verified = is_match
    db.commit()

    action_label = "EVIDENCE_VERIFIED_SUCCESS" if is_match else "EVIDENCE_HASH_MISMATCH"
    log_audit_event(
        db, current_user, action_label, target_type="EvidenceFile", target_id=evidence.id,
        details=f"Integrity check performed. Match={is_match}. Hash={current_hash[:16]}..."
    )

    return {
        "evidence_id": evidence.id,
        "filename": evidence.filename,
        "recorded_hash": evidence.sha256_hash,
        "current_hash": current_hash,
        "status": "INTEGRITY_VERIFIED" if is_match else "HASH_MISMATCH",
        "is_verified": is_match,
        "message": "Evidence SHA-256 cryptographic checksum verified intact." if is_match else "WARNING: Evidence file checksum mismatch! File content may have been modified."
    }

@router.get("/{evidence_id}/download")
def download_raw_evidence_file(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    evidence = db.query(EvidenceFile).filter(EvidenceFile.id == evidence_id).first()
    if not evidence or not os.path.exists(evidence.file_path):
        raise HTTPException(status_code=404, detail="Evidence file not found")

    log_audit_event(
        db, current_user, "EVIDENCE_DOWNLOAD", target_type="EvidenceFile", target_id=evidence.id,
        details=f"Downloaded raw evidence file '{evidence.filename}'"
    )

    return FileResponse(path=evidence.file_path, filename=evidence.filename, media_type="application/octet-stream")
