from typing import List, Optional
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import AuditLog, User
from app.schemas.schemas import AuditLogOut
from app.api.deps import get_current_user

router = APIRouter(prefix="/audit", tags=["Audit Trail"])

@router.get("", response_model=List[AuditLogOut])
def get_audit_logs(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    action: Optional[str] = None,
    username: Optional[str] = None,
    limit: int = 100
):
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action.ilike(f"%{action}%"))
    if username:
        query = query.filter(AuditLog.username.ilike(f"%{username}%"))
    
    return query.order_by(AuditLog.timestamp.desc()).limit(limit).all()
