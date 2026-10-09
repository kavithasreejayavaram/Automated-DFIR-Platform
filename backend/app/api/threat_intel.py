from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import IndicatorOfCompromise, NormalizedEvent, User
from app.schemas.schemas import IOCOut, IOCCreate
from app.engine.threat_intel import ThreatIntelEngine, seed_synthetic_iocs
from app.api.deps import get_current_user, log_audit_event

router = APIRouter(prefix="/iocs", tags=["Threat Intelligence & IOC Correlation"])

@router.get("", response_model=List[IOCOut])
def get_iocs(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    ioc_type: Optional[str] = None
):
    seed_synthetic_iocs(db)
    query = db.query(IndicatorOfCompromise)
    if ioc_type:
        query = query.filter(IndicatorOfCompromise.ioc_type == ioc_type)
    return query.order_by(IndicatorOfCompromise.last_updated.desc()).all()

@router.post("", response_model=IOCOut)
def add_ioc(
    ioc_in: IOCCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    existing = db.query(IndicatorOfCompromise).filter(
        IndicatorOfCompromise.ioc_value == ioc_in.ioc_value
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="IOC value already exists in threat database.")

    ioc = IndicatorOfCompromise(
        ioc_value=ioc_in.ioc_value,
        ioc_type=ioc_in.ioc_type,
        threat_level=ioc_in.threat_level,
        description=ioc_in.description,
        source=ioc_in.source,
        is_synthetic=ioc_in.is_synthetic
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)

    log_audit_event(
        db, current_user, "IOC_ADDED", target_type="IndicatorOfCompromise", target_id=ioc.id,
        details=f"Added {ioc.ioc_type} IOC '{ioc.ioc_value}' with threat level {ioc.threat_level}"
    )

    return ioc

@router.get("/matches")
def get_ioc_matches_in_logs(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    events = db.query(NormalizedEvent).all()
    matches = ThreatIntelEngine.match_events_against_iocs(db, events)
    return {
        "total_matches": len(matches),
        "matches": matches
    }

@router.get("/lookup/{ioc_value}")
def external_threat_lookup(
    ioc_value: str,
    ioc_type: str = "ip",
    current_user: User = Depends(get_current_user)
):
    res = ThreatIntelEngine.external_lookup(ioc_value, ioc_type)
    return res
