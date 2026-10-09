from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import Alert, DetectionRule, User
from app.schemas.schemas import AlertOut, DetectionRuleOut
from app.api.deps import get_current_user, require_admin, log_audit_event
from app.engine.detection import seed_detection_rules

router = APIRouter(prefix="/alerts", tags=["Alerts & Detection Rules"])

@router.get("", response_model=List[AlertOut])
def get_alerts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    
    alerts = query.order_by(Alert.timestamp.desc()).limit(limit).all()
    return alerts

@router.get("/rules", response_model=List[DetectionRuleOut])
def get_detection_rules(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    seed_detection_rules(db)
    return db.query(DetectionRule).all()

@router.put("/rules/{rule_id}/toggle", response_model=DetectionRuleOut)
def toggle_detection_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    
    rule.enabled = not rule.enabled
    db.commit()
    db.refresh(rule)

    log_audit_event(
        db, admin, "RULE_TOGGLED", target_type="DetectionRule", target_id=rule.id,
        details=f"Rule '{rule.name}' ({rule.rule_code}) status set to enabled={rule.enabled}"
    )

    return rule
