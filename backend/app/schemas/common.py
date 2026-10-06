from __future__ import annotations
from datetime import datetime
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from app.models.all import Role, ScanStatus, Severity, Confidence
from uuid import UUID
from typing import Literal

class APIError(BaseModel):
    code: str
    message: str
    request_id: str

class UserOut(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id: UUID; email: EmailStr; name: str; role: Role

class AuthResponse(BaseModel):
    access_token: str; refresh_token: str; token_type: str="bearer"; user: UserOut

class RegisterIn(BaseModel):
    email: EmailStr; name: str=Field(min_length=2,max_length=160); password: str=Field(min_length=12,max_length=128)

class LoginIn(BaseModel):
    email: EmailStr; password: str=Field(min_length=1,max_length=128)

class RefreshIn(BaseModel): refresh_token: str

class ScopeIn(BaseModel): kind: str; value: str; allowed: bool=True

class TargetCreate(BaseModel):
    name: str=Field(min_length=2,max_length=160)
    root_domain: str=Field(min_length=3,max_length=253)
    authorization_status: Literal["PENDING","AUTHORIZED","REVOKED"]="PENDING"
    notes: str|None=None
    scopes: list[ScopeIn]=Field(default_factory=list)
    scan_config: dict=Field(default_factory=dict)

class TargetUpdate(BaseModel):
    name: str|None=None; authorization_status: Literal["PENDING","AUTHORIZED","REVOKED"]|None=None; notes: str|None=None; scopes: list[ScopeIn]|None=None; scan_config: dict|None=None

class TargetOut(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id: UUID; name: str; root_domain: str; authorization_status: str; notes: str|None; scan_config: dict; created_at: datetime

class TargetDetailOut(TargetOut):
    scopes: list[ScopeIn] = Field(default_factory=list)

class ScanCreate(BaseModel):
    target_id: UUID
    profile: str=Field(default="Quick Audit", max_length=64)

class ScanOut(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id: UUID; target_id: UUID; requested_by: UUID; status: ScanStatus; profile: str; scope_snapshot: dict; started_at: datetime|None; ended_at: datetime|None; current_module: str|None; modules_completed: int; final_score: float|None; error: str|None; created_at: datetime

class FindingOut(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id: UUID; scan_id: UUID; title: str; category: str; severity: Severity; confidence: Confidence; cwe: str|None; owasp_category: str|None; description: str; evidence: dict; affected_url: str|None; impact: str; remediation: str; references: list; detected_at: datetime

class CloudflareConnectIn(BaseModel):
    token: str=Field(min_length=20,max_length=4096)
    account_id: str|None=None; zone_id: str|None=None; label: str="Cloudflare"

class AdminUserUpdate(BaseModel):
    role: Literal["ADMIN","ANALYST","VIEWER"]|None=None
    is_active: bool|None=None

class AIAnalysisOut(BaseModel):
    model_config=ConfigDict(from_attributes=True)
    id: UUID; scan_id: UUID; provider: str; model: str; status: str; output: dict|None; confidence: float|None; error: str|None; created_at: datetime
