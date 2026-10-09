from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, EmailStr, ConfigDict

# Token
class Token(BaseModel):
    access_token: str
    token_type: str
    user: "UserOut"

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

# User
class UserBase(BaseModel):
    username: str
    email: EmailStr
    role: str = "analyst"

class UserCreate(UserBase):
    password: str

class UserOut(UserBase):
    id: str
    is_active: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

# Evidence File
class EvidenceFileOut(BaseModel):
    id: str
    filename: str
    file_size: int
    sha256_hash: str
    line_count: int
    acquisition_time: datetime
    analyst_id: Optional[str]
    storage_type: str
    is_verified: bool
    model_config = ConfigDict(from_attributes=True)

# Normalized Event
class NormalizedEventOut(BaseModel):
    id: str
    evidence_file_id: str
    timestamp: datetime
    hostname: Optional[str]
    username: Optional[str]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    event_type: str
    event_description: Optional[str]
    process_name: Optional[str]
    auth_result: Optional[str]
    raw_record: str
    model_config = ConfigDict(from_attributes=True)

# Detection Rule
class DetectionRuleOut(BaseModel):
    id: str
    rule_code: str
    name: str
    description: str
    severity: str
    confidence: str
    mitre_technique_id: Optional[str]
    mitre_technique_name: Optional[str]
    query_logic: str
    remediation_steps: Optional[str]
    enabled: bool
    model_config = ConfigDict(from_attributes=True)

# Alert
class AlertOut(BaseModel):
    id: str
    rule_id: str
    evidence_file_id: Optional[str]
    timestamp: datetime
    hostname: Optional[str]
    username: Optional[str]
    source_ip: Optional[str]
    severity: str
    confidence: str
    trigger_reason: str
    recommended_actions: Optional[str]
    status: str
    rule: Optional[DetectionRuleOut] = None
    model_config = ConfigDict(from_attributes=True)

# Analyst Note
class NoteCreate(BaseModel):
    content: str

class AnalystNoteOut(BaseModel):
    id: str
    incident_id: str
    analyst_id: str
    content: str
    created_at: datetime
    analyst_username: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)

# Incident
class IncidentCreate(BaseModel):
    title: str
    description: str
    severity: str = "Medium"
    alert_ids: Optional[List[str]] = None

class IncidentUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None  # Open, Investigating, Resolved, False Positive
    severity: Optional[str] = None
    resolution_notes: Optional[str] = None

class IncidentOut(BaseModel):
    id: str
    title: str
    description: str
    status: str
    severity: str
    created_by_id: Optional[str]
    created_at: datetime
    updated_at: datetime
    resolution_notes: Optional[str]
    alerts_count: Optional[int] = 0
    events_count: Optional[int] = 0
    notes: Optional[List[AnalystNoteOut]] = []
    model_config = ConfigDict(from_attributes=True)

# Indicator of Compromise
class IOCCreate(BaseModel):
    ioc_value: str
    ioc_type: str  # ip, domain, file_hash, url
    threat_level: str = "Medium"
    description: Optional[str] = None
    source: str = "Manual Analyst Import"
    is_synthetic: bool = True

class IOCOut(BaseModel):
    id: str
    ioc_value: str
    ioc_type: str
    threat_level: str
    description: Optional[str]
    source: str
    last_updated: datetime
    is_synthetic: bool
    model_config = ConfigDict(from_attributes=True)

# Audit Log
class AuditLogOut(BaseModel):
    id: str
    user_id: Optional[str]
    username: Optional[str]
    action: str
    target_type: Optional[str]
    target_id: Optional[str]
    details: Optional[str]
    timestamp: datetime
    client_ip: Optional[str]
    model_config = ConfigDict(from_attributes=True)

# Report
class ReportOut(BaseModel):
    id: str
    incident_id: str
    report_title: str
    file_format: str
    created_at: datetime
    file_path: str
    model_config = ConfigDict(from_attributes=True)

# Analytics Dashboard Schema
class DashboardAnalytics(BaseModel):
    total_events: int
    total_evidence_files: int
    total_alerts: int
    active_incidents: int
    alerts_by_severity: Dict[str, int]
    incidents_by_status: Dict[str, int]
    top_affected_hosts: List[Dict[str, Any]]
    top_affected_users: List[Dict[str, Any]]
    event_timeline: List[Dict[str, Any]]
    recent_alerts: List[AlertOut]
    recent_evidence: List[EvidenceFileOut]

# Benchmark Results
class BenchmarkResult(BaseModel):
    total_logs_processed: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    detection_summary: Dict[str, int]
