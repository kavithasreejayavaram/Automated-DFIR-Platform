from datetime import datetime, timezone
import uuid
from sqlalchemy import (
    Column, String, Integer, DateTime, ForeignKey, Text, Boolean, Table, Float
)
from sqlalchemy.orm import relationship
from app.db.database import Base

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="analyst")  # 'admin' or 'analyst'
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    notes = relationship("AnalystNote", back_populates="analyst")
    audit_logs = relationship("AuditLog", back_populates="user")
    reports = relationship("Report", back_populates="generated_by")


class EvidenceFile(Base):
    __tablename__ = "evidence_files"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    filename = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size = Column(Integer, nullable=False)  # bytes
    sha256_hash = Column(String(64), nullable=False, index=True)
    line_count = Column(Integer, default=0)
    acquisition_time = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    analyst_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    storage_type = Column(String(50), default="local")
    is_verified = Column(Boolean, default=True)

    events = relationship("NormalizedEvent", back_populates="evidence_file", cascade="all, delete-orphan")
    analyst = relationship("User")


class NormalizedEvent(Base):
    __tablename__ = "normalized_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    evidence_file_id = Column(String(36), ForeignKey("evidence_files.id"), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    hostname = Column(String(100), nullable=True, index=True)
    username = Column(String(100), nullable=True, index=True)
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    event_description = Column(Text, nullable=True)
    process_name = Column(String(255), nullable=True)
    auth_result = Column(String(20), nullable=True)  # 'SUCCESS', 'FAILURE', 'UNKNOWN'
    raw_record = Column(Text, nullable=False)
    event_hash = Column(String(64), nullable=True, index=True)

    evidence_file = relationship("EvidenceFile", back_populates="events")


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    rule_code = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(150), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)  # 'Low', 'Medium', 'High', 'Critical'
    confidence = Column(String(20), nullable=False)  # 'Low', 'Medium', 'High'
    mitre_technique_id = Column(String(20), nullable=True)
    mitre_technique_name = Column(String(100), nullable=True)
    query_logic = Column(Text, nullable=False)
    remediation_steps = Column(Text, nullable=True)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    alerts = relationship("Alert", back_populates="rule")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    rule_id = Column(String(36), ForeignKey("detection_rules.id"), nullable=False)
    evidence_file_id = Column(String(36), ForeignKey("evidence_files.id"), nullable=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    hostname = Column(String(100), nullable=True)
    username = Column(String(100), nullable=True)
    source_ip = Column(String(45), nullable=True)
    severity = Column(String(20), nullable=False)
    confidence = Column(String(20), nullable=False)
    trigger_reason = Column(Text, nullable=False)
    trigger_events_json = Column(Text, nullable=True)  # JSON array of event IDs
    recommended_actions = Column(Text, nullable=True)
    status = Column(String(20), default="New")  # 'New', 'Acknowledged', 'In Incident', 'Dismissed'

    rule = relationship("DetectionRule", back_populates="alerts")
    incident_associations = relationship("IncidentEvent", back_populates="alert")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    status = Column(String(30), default="Open")  # 'Open', 'Investigating', 'Resolved', 'False Positive'
    severity = Column(String(20), default="Medium")  # 'Low', 'Medium', 'High', 'Critical'
    created_by_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    resolution_notes = Column(Text, nullable=True)

    created_by = relationship("User")
    event_associations = relationship("IncidentEvent", back_populates="incident", cascade="all, delete-orphan")
    notes = relationship("AnalystNote", back_populates="incident", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="incident")


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    event_id = Column(String(36), ForeignKey("normalized_events.id"), nullable=True)
    alert_id = Column(String(36), ForeignKey("alerts.id"), nullable=True)

    incident = relationship("Incident", back_populates="event_associations")
    alert = relationship("Alert", back_populates="incident_associations")
    event = relationship("NormalizedEvent")


class IndicatorOfCompromise(Base):
    __tablename__ = "indicators_of_compromise"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    ioc_value = Column(String(255), nullable=False, index=True)
    ioc_type = Column(String(30), nullable=False)  # 'ip', 'domain', 'file_hash', 'url'
    threat_level = Column(String(20), default="Medium")  # 'Low', 'Medium', 'High', 'Critical'
    description = Column(Text, nullable=True)
    source = Column(String(100), default="Synthetic Dataset")
    last_updated = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    is_synthetic = Column(Boolean, default=True)


class AnalystNote(Base):
    __tablename__ = "analyst_notes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    analyst_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    incident = relationship("Incident", back_populates="notes")
    analyst = relationship("User", back_populates="notes")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    username = Column(String(50), nullable=True)
    action = Column(String(100), nullable=False)
    target_type = Column(String(50), nullable=True)
    target_id = Column(String(100), nullable=True)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    client_ip = Column(String(45), nullable=True)

    user = relationship("User", back_populates="audit_logs")


class Report(Base):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=False)
    generated_by_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    report_title = Column(String(200), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_format = Column(String(10), default="PDF")  # 'PDF' or 'JSON'
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    incident = relationship("Incident", back_populates="reports")
    generated_by = relationship("User", back_populates="reports")
