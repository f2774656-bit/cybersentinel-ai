from __future__ import annotations
from datetime import datetime, timezone
import enum, uuid
from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, Index, LargeBinary
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.database import Base

def utcnow(): return datetime.now(timezone.utc)

def uid(): return uuid.uuid4()

class Role(str, enum.Enum): ADMIN="ADMIN"; ANALYST="ANALYST"; VIEWER="VIEWER"
class ScanStatus(str, enum.Enum): QUEUED="QUEUED"; VALIDATING="VALIDATING"; RUNNING="RUNNING"; ANALYZING="ANALYZING"; COMPLETED="COMPLETED"; FAILED="FAILED"; CANCELLED="CANCELLED"
class Severity(str, enum.Enum): INFO="INFO"; LOW="LOW"; MEDIUM="MEDIUM"; HIGH="HIGH"; CRITICAL="CRITICAL"
class Confidence(str, enum.Enum): LOW="LOW"; MEDIUM="MEDIUM"; HIGH="HIGH"

class User(Base):
    __tablename__="users"
    id: Mapped[uuid.UUID]=mapped_column(primary_key=True, default=uid)
    email: Mapped[str]=mapped_column(String(320), unique=True, index=True)
    name: Mapped[str]=mapped_column(String(160))
    password_hash: Mapped[str]=mapped_column(String(512))
    role: Mapped[Role]=mapped_column(Enum(Role), default=Role.VIEWER)
    is_active: Mapped[bool]=mapped_column(Boolean, default=True)
    failed_logins: Mapped[int]=mapped_column(Integer, default=0)
    locked_until: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    sessions=relationship("Session", back_populates="user", cascade="all, delete-orphan")

class Session(Base):
    __tablename__="sessions"
    id: Mapped[uuid.UUID]=mapped_column(primary_key=True, default=uid)
    user_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str]=mapped_column(String(128), unique=True, index=True)
    expires_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=utcnow)
    user=relationship("User", back_populates="sessions")

class Target(Base):
    __tablename__="targets"
    id: Mapped[uuid.UUID]=mapped_column(primary_key=True, default=uid)
    owner_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str]=mapped_column(String(160))
    root_domain: Mapped[str]=mapped_column(String(253), index=True)
    authorization_status: Mapped[str]=mapped_column(String(32), default="PENDING")
    notes: Mapped[str|None]=mapped_column(Text)
    scan_config: Mapped[dict]=mapped_column(JSON, default=dict)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    scopes=relationship("TargetScope", back_populates="target", cascade="all, delete-orphan")
    owner=relationship("User")

class TargetScope(Base):
    __tablename__="target_scopes"
    id: Mapped[uuid.UUID]=mapped_column(primary_key=True, default=uid)
    target_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str]=mapped_column(String(32))
    value: Mapped[str]=mapped_column(String(512))
    allowed: Mapped[bool]=mapped_column(Boolean, default=True)
    target=relationship("Target", back_populates="scopes")
    __table_args__=(UniqueConstraint("target_id","kind","value", name="uq_target_scope"),)

class Scan(Base):
    __tablename__="scans"
    id: Mapped[uuid.UUID]=mapped_column(primary_key=True, default=uid)
    target_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("targets.id", ondelete="CASCADE"), index=True)
    requested_by: Mapped[uuid.UUID]=mapped_column(ForeignKey("users.id"), index=True)
    status: Mapped[ScanStatus]=mapped_column(Enum(ScanStatus), default=ScanStatus.QUEUED, index=True)
    profile: Mapped[str]=mapped_column(String(64))
    scope_snapshot: Mapped[dict]=mapped_column(JSON, default=dict)
    started_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
    current_module: Mapped[str|None]=mapped_column(String(64))
    modules_completed: Mapped[int]=mapped_column(Integer, default=0)
    final_score: Mapped[float|None]=mapped_column(Float)
    error: Mapped[str|None]=mapped_column(Text)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=utcnow)
    target=relationship("Target")
    modules=relationship("ScanModule", back_populates="scan", cascade="all, delete-orphan")
    events=relationship("ScanEvent", back_populates="scan", cascade="all, delete-orphan")
    findings=relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

class ScanModule(Base):
    __tablename__="scan_modules"
    id: Mapped[uuid.UUID]=mapped_column(primary_key=True, default=uid)
    scan_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    name: Mapped[str]=mapped_column(String(80))
    status: Mapped[str]=mapped_column(String(32), default="QUEUED")
    started_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
    error: Mapped[str|None]=mapped_column(Text)
    scan=relationship("Scan", back_populates="modules")

class ScanEvent(Base):
    __tablename__="scan_events"
    id: Mapped[uuid.UUID]=mapped_column(primary_key=True, default=uid)
    scan_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    level: Mapped[str]=mapped_column(String(16), default="INFO")
    message: Mapped[str]=mapped_column(Text)
    event_type: Mapped[str]=mapped_column(String(64), default="scan")
    event_metadata: Mapped[dict]=mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    scan=relationship("Scan", back_populates="events")

class Finding(Base):
    __tablename__="findings"
    id: Mapped[uuid.UUID]=mapped_column(primary_key=True, default=uid)
    scan_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    title: Mapped[str]=mapped_column(String(240))
    category: Mapped[str]=mapped_column(String(80))
    severity: Mapped[Severity]=mapped_column(Enum(Severity), index=True)
    confidence: Mapped[Confidence]=mapped_column(Enum(Confidence), index=True)
    cwe: Mapped[str|None]=mapped_column(String(32))
    owasp_category: Mapped[str|None]=mapped_column(String(64))
    description: Mapped[str]=mapped_column(Text)
    evidence: Mapped[dict]=mapped_column(JSON, default=dict)
    affected_url: Mapped[str|None]=mapped_column(String(2048))
    impact: Mapped[str]=mapped_column(Text)
    remediation: Mapped[str]=mapped_column(Text)
    references: Mapped[list]=mapped_column(JSON, default=list)
    detected_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    scan=relationship("Scan", back_populates="findings")
    evidence_items=relationship("FindingEvidence", back_populates="finding", cascade="all, delete-orphan")
    __table_args__=(Index("ix_findings_scan_severity","scan_id","severity"),)

class FindingEvidence(Base):
    __tablename__="finding_evidence"
    id: Mapped[uuid.UUID]=mapped_column(primary_key=True, default=uid)
    finding_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str]=mapped_column(String(64))
    source: Mapped[str]=mapped_column(String(64))
    content: Mapped[dict]=mapped_column(JSON, default=dict)
    captured_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=utcnow)
    finding=relationship("Finding", back_populates="evidence_items")

class CloudflareConnection(Base):
    __tablename__="cloudflare_connections"
    id: Mapped[uuid.UUID]=mapped_column(primary_key=True, default=uid)
    user_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    account_id: Mapped[str|None]=mapped_column(String(64))
    zone_id: Mapped[str|None]=mapped_column(String(64))
    token_encrypted: Mapped[str]=mapped_column(Text)
    label: Mapped[str]=mapped_column(String(160), default="Cloudflare")
    last_tested_at: Mapped[datetime|None]=mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=utcnow)

class AIAnalysis(Base):
    __tablename__="ai_analyses"
    id: Mapped[uuid.UUID]=mapped_column(primary_key=True, default=uid)
    scan_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str]=mapped_column(String(64))
    model: Mapped[str]=mapped_column(String(160))
    status: Mapped[str]=mapped_column(String(32), default="QUEUED")
    input_evidence: Mapped[dict]=mapped_column(JSON, default=dict)
    output: Mapped[dict|None]=mapped_column(JSON)
    confidence: Mapped[float|None]=mapped_column(Float)
    error: Mapped[str|None]=mapped_column(Text)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

class Report(Base):
    __tablename__="reports"
    id: Mapped[uuid.UUID]=mapped_column(primary_key=True, default=uid)
    scan_id: Mapped[uuid.UUID]=mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    format: Mapped[str]=mapped_column(String(16))
    status: Mapped[str]=mapped_column(String(32), default="QUEUED")
    file_path: Mapped[str|None]=mapped_column(String(2048))
    content: Mapped[str|None]=mapped_column(Text)
    blob: Mapped[bytes|None]=mapped_column(LargeBinary)
    created_by: Mapped[uuid.UUID]=mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=utcnow)

class AuditLog(Base):
    __tablename__="audit_logs"
    id: Mapped[uuid.UUID]=mapped_column(primary_key=True, default=uid)
    user_id: Mapped[uuid.UUID|None]=mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    action: Mapped[str]=mapped_column(String(80), index=True)
    resource_type: Mapped[str|None]=mapped_column(String(80))
    resource_id: Mapped[str|None]=mapped_column(String(64))
    ip_address: Mapped[str|None]=mapped_column(String(64))
    details: Mapped[dict]=mapped_column(JSON, default=dict)
    created_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=utcnow, index=True)

class SystemSetting(Base):
    __tablename__="system_settings"
    key: Mapped[str]=mapped_column(String(128), primary_key=True)
    value: Mapped[str]=mapped_column(Text)
    updated_at: Mapped[datetime]=mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
