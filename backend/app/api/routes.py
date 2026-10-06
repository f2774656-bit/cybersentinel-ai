from __future__ import annotations
import uuid, re
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import current_user, require_roles
from app.core.config import get_settings
from app.core.security import create_access_token, create_refresh_token, decode_token, decrypt_secret, encrypt_secret, hash_password, hash_token, verify_password
from app.db.database import get_db, ping_db
from app.models.all import AIAnalysis, AuditLog, CloudflareConnection, Finding, FindingEvidence, Report, Role, Scan, ScanEvent, ScanModule, ScanStatus, Session, Target, TargetScope, User
from app.schemas.common import *
from app.services.audit import audit
from app.services.cloudflare import CloudflareClient, CloudflareError
from app.services.queue import QUEUE_AI, QUEUE_REPORT, QUEUE_SCAN, enqueue, redis_ping, worker_statuses
from app.services.reports import build_report
from app.services.scoring import breakdown
from app.services.scope import ScopeViolation, normalize_domain

router = APIRouter(prefix="/api")
settings = get_settings()

async def rate_limit(key: str, limit: int, seconds: int) -> bool:
    from app.services.queue import redis
    r = redis()
    try:
        n = await r.incr(key)
        if n == 1:
            await r.expire(key, seconds)
        return n <= limit
    finally:
        await r.aclose()

@router.post("/auth/register", response_model=AuthResponse)
async def register(data: RegisterIn, request: Request, db: AsyncSession = Depends(get_db)):
    if not settings.registration_enabled:
        raise HTTPException(403, "Registration is disabled")
    ip = request.client.host if request.client else "unknown"
    if not await rate_limit(f"rl:register:{ip}", 5, 900):
        raise HTTPException(429, "Too many registration attempts")
    email = data.email.lower()
    if (await db.execute(select(User).where(User.email == email))).scalar_one_or_none():
        raise HTTPException(409, "Email already registered")
    count = (await db.execute(select(func.count(User.id)))).scalar_one()
    role = Role.ADMIN if count == 0 else Role.VIEWER
    user = User(email=email, name=data.name.strip(), password_hash=hash_password(data.password), role=role)
    db.add(user)
    await db.flush()
    if role == Role.ADMIN:
        default_target = Target(
            owner_id=user.id,
            name=settings.default_target,
            root_domain=settings.default_target,
            authorization_status="PENDING",
            notes="Default target; explicit authorization is required before scanning.",
            scan_config={},
        )
        db.add(default_target)
        await db.flush()
        db.add(TargetScope(target_id=default_target.id, kind="host", value=settings.default_target, allowed=True))
    session = Session(user_id=user.id, token_hash="pending", expires_at=datetime.now(timezone.utc) + timedelta(days=settings.jwt_refresh_days))
    db.add(session)
    await db.flush()
    refresh_token = create_refresh_token(str(user.id), str(session.id))
    session.token_hash = hash_token(refresh_token)
    await audit(db, user.id, "register", "user", user.id, ip)
    await db.commit()
    return AuthResponse(access_token=create_access_token(str(user.id), user.role.value), refresh_token=refresh_token, user=user)

@router.post("/auth/login", response_model=AuthResponse)
async def login(data: LoginIn, request: Request, db: AsyncSession = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    if not await rate_limit(f"rl:login:{ip}", 15, 300):
        raise HTTPException(429, "Too many login attempts")
    user = (await db.execute(select(User).where(User.email == data.email.lower()))).scalar_one_or_none()
    now = datetime.now(timezone.utc)
    if not user:
        raise HTTPException(401, "Invalid credentials")
    if user.locked_until and user.locked_until > now:
        raise HTTPException(423, "Account temporarily locked")
    if not verify_password(data.password, user.password_hash):
        user.failed_logins += 1
        if user.failed_logins >= 8:
            user.locked_until = now + timedelta(minutes=15)
            user.failed_logins = 0
        await audit(db, user.id, "login_failed", "user", user.id, ip)
        await db.commit()
        raise HTTPException(401, "Invalid credentials")
    user.failed_logins = 0
    user.locked_until = None
    session = Session(user_id=user.id, token_hash="pending", expires_at=now + timedelta(days=settings.jwt_refresh_days))
    db.add(session)
    await db.flush()
    refresh_token = create_refresh_token(str(user.id), str(session.id))
    session.token_hash = hash_token(refresh_token)
    await audit(db, user.id, "login", "user", user.id, ip)
    await db.commit()
    return AuthResponse(access_token=create_access_token(str(user.id), user.role.value), refresh_token=refresh_token, user=user)

@router.post("/auth/refresh", response_model=AuthResponse)
async def refresh(data: RefreshIn, db: AsyncSession = Depends(get_db)):
    payload = decode_token(data.refresh_token, "refresh")
    session = await db.get(Session, payload.get("sid"))
    user = await db.get(User, payload.get("sub"))
    if not session or session.revoked_at or session.expires_at < datetime.now(timezone.utc) or not user or not user.is_active or session.token_hash != hash_token(data.refresh_token):
        raise HTTPException(401, "Session invalid")
    session.revoked_at = datetime.now(timezone.utc)
    new = Session(user_id=user.id, token_hash="pending", expires_at=datetime.now(timezone.utc) + timedelta(days=settings.jwt_refresh_days))
    db.add(new)
    await db.flush()
    new_refresh_token = create_refresh_token(str(user.id), str(new.id))
    new.token_hash = hash_token(new_refresh_token)
    await db.commit()
    return AuthResponse(access_token=create_access_token(str(user.id), user.role.value), refresh_token=new_refresh_token, user=user)

@router.post("/auth/logout")
async def logout(data: RefreshIn, request: Request, db: AsyncSession = Depends(get_db)):
    payload = decode_token(data.refresh_token, "refresh")
    session = await db.get(Session, payload.get("sid"))
    if session and session.token_hash == hash_token(data.refresh_token):
        session.revoked_at = datetime.now(timezone.utc)
    if payload.get("sub"):
        await audit(db, payload["sub"], "logout", "session", payload.get("sid"), request.client.host if request.client else None)
    await db.commit()
    return {"ok": True}

@router.get("/auth/me", response_model=UserOut)
async def me(user=Depends(current_user)):
    return user

@router.get("/dashboard/summary")
async def dashboard_summary(user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    targets = (await db.execute(select(func.count(Target.id)).where(Target.owner_id == user.id))).scalar_one()
    scans = (await db.execute(select(func.count(Scan.id)).where(Scan.requested_by == user.id))).scalar_one()
    findings = (await db.execute(select(func.count(Finding.id)).join(Scan).where(Scan.requested_by == user.id))).scalar_one()
    severities = {}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        severities[sev] = (await db.execute(select(func.count(Finding.id)).join(Scan).where(Scan.requested_by == user.id, Finding.severity == sev))).scalar_one()
    recent = (await db.execute(select(Scan).where(Scan.requested_by == user.id).order_by(Scan.created_at.desc()).limit(8))).scalars().all()
    latest_completed = next((x for x in recent if x.status == ScanStatus.COMPLETED), None)
    return {"targets": targets, "scans": scans, "findings": findings, "severities": severities, "latest_completed_score": latest_completed.final_score if latest_completed else None, "recent_scans": [ScanOut.model_validate(x).model_dump(mode="json") for x in recent]}

@router.get("/targets", response_model=list[TargetOut])
async def list_targets(user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    return (await db.execute(select(Target).where(Target.owner_id == user.id).order_by(Target.created_at.desc()))).scalars().all()

@router.post("/targets", response_model=TargetOut)
async def create_target(data: TargetCreate, request: Request, user=Depends(require_roles(Role.ADMIN, Role.ANALYST)), db: AsyncSession = Depends(get_db)):
    try:
        root = normalize_domain(data.root_domain)
    except ScopeViolation as exc:
        raise HTTPException(400, str(exc))
    target = Target(owner_id=user.id, name=data.name.strip(), root_domain=root, authorization_status=data.authorization_status, notes=data.notes, scan_config=data.scan_config)
    db.add(target)
    await db.flush()
    for item in data.scopes:
        value = item.value.strip()
        if item.kind == "host":
            value = normalize_domain(value)
        elif item.kind == "path":
            if not value.startswith("/"):
                raise HTTPException(400, "Path scopes must begin with /")
        elif item.kind == "ip":
            # IP scopes are retained as authorization metadata; actual scan destinations still pass the same public-IP checks.
            value = value.strip()
        else:
            raise HTTPException(400, "Unsupported scope kind")
        db.add(TargetScope(target_id=target.id, kind=item.kind, value=value, allowed=item.allowed))
    await audit(db, user.id, "target_create", "target", target.id, request.client.host if request.client else None)
    await db.commit()
    await db.refresh(target)
    return target

@router.get("/targets/{target_id}", response_model=TargetDetailOut)
async def get_target(target_id: uuid.UUID, user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if not target or (target.owner_id != user.id and user.role != Role.ADMIN):
        raise HTTPException(404, "Target not found")
    scopes = (await db.execute(select(TargetScope).where(TargetScope.target_id == target_id))).scalars().all()
    return {"id":target.id,"name":target.name,"root_domain":target.root_domain,"authorization_status":target.authorization_status,"notes":target.notes,"scan_config":target.scan_config,"created_at":target.created_at,"scopes":[{"kind":x.kind,"value":x.value,"allowed":x.allowed} for x in scopes]}

@router.patch("/targets/{target_id}", response_model=TargetOut)
async def update_target(target_id: uuid.UUID, data: TargetUpdate, request: Request, user=Depends(require_roles(Role.ADMIN, Role.ANALYST)), db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if not target or (target.owner_id != user.id and user.role != Role.ADMIN):
        raise HTTPException(404, "Target not found")
    for field in ("name", "authorization_status", "notes", "scan_config"):
        value = getattr(data, field)
        if value is not None:
            setattr(target, field, value)
    if data.scopes is not None:
        await db.execute(delete(TargetScope).where(TargetScope.target_id == target.id))
        for item in data.scopes:
            value = item.value.strip()
            if item.kind == "host": value = normalize_domain(value)
            elif item.kind == "path" and not value.startswith("/"): raise HTTPException(400, "Path scopes must begin with /")
            elif item.kind not in {"host", "path", "ip"}: raise HTTPException(400, "Unsupported scope kind")
            db.add(TargetScope(target_id=target.id, kind=item.kind, value=value, allowed=item.allowed))
    await audit(db, user.id, "target_update", "target", target.id, request.client.host if request.client else None)
    await db.commit()
    await db.refresh(target)
    return target

@router.delete("/targets/{target_id}")
async def delete_target(target_id: uuid.UUID, request: Request, user=Depends(require_roles(Role.ADMIN, Role.ANALYST)), db: AsyncSession = Depends(get_db)):
    target = await db.get(Target, target_id)
    if not target or (target.owner_id != user.id and user.role != Role.ADMIN):
        raise HTTPException(404, "Target not found")
    await audit(db, user.id, "target_delete", "target", target.id, request.client.host if request.client else None)
    await db.delete(target)
    await db.commit()
    return {"ok": True}

@router.post("/scans", response_model=ScanOut)
async def create_scan(data: ScanCreate, request: Request, user=Depends(require_roles(Role.ADMIN, Role.ANALYST)), db: AsyncSession = Depends(get_db)):
    if not await rate_limit(f"rl:scan:{user.id}", 20, 3600):
        raise HTTPException(429, "Scan rate limit exceeded")
    target = await db.get(Target, data.target_id)
    if not target or (target.owner_id != user.id and user.role != Role.ADMIN):
        raise HTTPException(404, "Target not found")
    if target.authorization_status.upper() != "AUTHORIZED":
        raise HTTPException(403, "Target must be explicitly AUTHORIZED before scanning")
    scope_rows = (await db.execute(select(TargetScope).where(TargetScope.target_id == target.id))).scalars().all()
    snapshot = {
        "allowed_hosts": [x.value for x in scope_rows if x.kind == "host" and x.allowed],
        "allowed_paths": [x.value for x in scope_rows if x.kind == "path" and x.allowed],
        "excluded_hosts": [x.value for x in scope_rows if x.kind == "host" and not x.allowed],
        "excluded_paths": [x.value for x in scope_rows if x.kind == "path" and not x.allowed],
        "authorized_ips": [x.value for x in scope_rows if x.kind == "ip" and x.allowed],
    }
    scan = Scan(target_id=target.id, requested_by=user.id, profile=data.profile, scope_snapshot=snapshot, status=ScanStatus.QUEUED)
    db.add(scan)
    await db.flush()
    await audit(db, user.id, "scan_create", "scan", scan.id, request.client.host if request.client else None, {"profile": data.profile, "target": target.root_domain})
    await db.commit()
    await enqueue(QUEUE_SCAN, {"scan_id": str(scan.id)})
    await db.refresh(scan)
    return scan

@router.get("/scans", response_model=list[ScanOut])
async def list_scans(user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    return (await db.execute(select(Scan).where(Scan.requested_by == user.id).order_by(Scan.created_at.desc()).limit(100))).scalars().all()

@router.get("/scans/{scan_id}")
async def get_scan(scan_id: uuid.UUID, user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan or (scan.requested_by != user.id and user.role != Role.ADMIN):
        raise HTTPException(404, "Scan not found")
    modules = (await db.execute(select(ScanModule).where(ScanModule.scan_id == scan_id).order_by(ScanModule.started_at))).scalars().all()
    events = (await db.execute(select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.created_at))).scalars().all()
    findings = (await db.execute(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.detected_at.desc()))).scalars().all()
    return {
        "scan": ScanOut.model_validate(scan).model_dump(mode="json"),
        "modules": [{"id": str(m.id), "name": m.name, "status": m.status, "started_at": m.started_at.isoformat() if m.started_at else None, "ended_at": m.ended_at.isoformat() if m.ended_at else None, "error": m.error} for m in modules],
        "events": [{"level": e.level, "message": e.message, "created_at": e.created_at.isoformat(), "metadata": e.event_metadata} for e in events],
        "findings": [FindingOut.model_validate(f).model_dump(mode="json") for f in findings],
        "score": breakdown(findings),
    }

@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: uuid.UUID, request: Request, user=Depends(require_roles(Role.ADMIN, Role.ANALYST)), db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan or (scan.requested_by != user.id and user.role != Role.ADMIN):
        raise HTTPException(404, "Scan not found")
    if scan.status in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}:
        return {"ok": True, "status": scan.status.value}
    scan.status = ScanStatus.CANCELLED
    await audit(db, user.id, "scan_cancel", "scan", scan.id, request.client.host if request.client else None)
    await db.commit()
    return {"ok": True}

@router.get("/findings", response_model=list[FindingOut])
async def list_findings(user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    return (await db.execute(select(Finding).join(Scan).where(Scan.requested_by == user.id).order_by(Finding.detected_at.desc()).limit(500))).scalars().all()

@router.get("/findings/{finding_id}", response_model=FindingOut)
async def get_finding(finding_id: uuid.UUID, user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    finding = await db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    scan = await db.get(Scan, finding.scan_id)
    if not scan or (scan.requested_by != user.id and user.role != Role.ADMIN):
        raise HTTPException(404, "Finding not found")
    return finding

@router.post("/cloudflare/connect")
async def cloudflare_connect(data: CloudflareConnectIn, request: Request, user=Depends(require_roles(Role.ADMIN, Role.ANALYST)), db: AsyncSession = Depends(get_db)):
    if not await rate_limit(f"rl:cfconnect:{user.id}", 10, 3600):
        raise HTTPException(429, "Cloudflare connection rate limit exceeded")
    client = CloudflareClient(data.token)
    try:
        test = await client.test(data.account_id, data.zone_id)
    except CloudflareError as exc:
        raise HTTPException(400, f"Cloudflare connection failed: {exc}")
    row = CloudflareConnection(user_id=user.id, account_id=data.account_id, zone_id=data.zone_id, token_encrypted=encrypt_secret(data.token), label=data.label, last_tested_at=datetime.now(timezone.utc))
    db.add(row)
    await audit(db, user.id, "cloudflare_connect", "cloudflare_connection", row.id, request.client.host if request.client else None, {"account_id": data.account_id, "zone_id": data.zone_id})
    await db.commit()
    return {"ok": True, "connection_id": str(row.id), "resource": test["resource"]}

def validate_cloudflare_id(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{2,64}", value):
        raise HTTPException(400, "Invalid Cloudflare identifier")
    return value

async def cf_client_for_user(user, db):
    row = (await db.execute(select(CloudflareConnection).where(CloudflareConnection.user_id == user.id).order_by(CloudflareConnection.created_at.desc()).limit(1))).scalar_one_or_none()
    if not row:
        if user.role == Role.ADMIN and settings.cloudflare_api_token:
            return None, CloudflareClient(settings.cloudflare_api_token)
        raise HTTPException(404, "No Cloudflare connection")
    try:
        token = decrypt_secret(row.token_encrypted)
    except Exception as exc:
        raise HTTPException(500, "Stored Cloudflare credential could not be decrypted") from exc
    return row, CloudflareClient(token)

@router.get("/cloudflare/status")
async def cloudflare_status(user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    try:
        row, client = await cf_client_for_user(user, db)
        account_id = row.account_id if row else settings.cloudflare_account_id
        zone_id = row.zone_id if row else settings.cloudflare_zone_id
        await client.test(account_id, zone_id)
        if row:
            row.last_tested_at = datetime.now(timezone.utc); await db.commit()
        return {"connected": True, "account_id": account_id, "zone_id": zone_id, "label": row.label if row else "Platform Cloudflare Token"}
    except HTTPException:
        return {"connected": False}
    except Exception as exc:
        return {"connected": False, "error": str(exc)[:500]}

@router.get("/cloudflare/accounts")
async def cloudflare_accounts(user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    _, client = await cf_client_for_user(user, db)
    try:
        return await client.accounts()
    except CloudflareError as exc:
        raise HTTPException(502, str(exc))

@router.get("/cloudflare/accounts/{account_id}")
async def cloudflare_account(account_id: str, user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    account_id=validate_cloudflare_id(account_id)
    _, client = await cf_client_for_user(user, db)
    try:
        return await client.account(account_id)
    except CloudflareError as exc:
        raise HTTPException(502, str(exc))

@router.get("/cloudflare/zones")
async def cloudflare_zones(user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    _, client = await cf_client_for_user(user, db)
    try:
        return await client.zones()
    except CloudflareError as exc:
        raise HTTPException(502, str(exc))

@router.get("/cloudflare/zones/{zone_id}")
async def cloudflare_zone(zone_id: str, user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    zone_id=validate_cloudflare_id(zone_id)
    _, client = await cf_client_for_user(user, db)
    try:
        return await client.zone(zone_id)
    except CloudflareError as exc:
        raise HTTPException(502, str(exc))

@router.get("/cloudflare/zones/{zone_id}/dns")
async def cloudflare_dns(zone_id: str, user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    zone_id=validate_cloudflare_id(zone_id)
    _, client = await cf_client_for_user(user, db)
    try:
        return await client.dns(zone_id)
    except CloudflareError as exc:
        raise HTTPException(502, str(exc))

@router.get("/cloudflare/zones/{zone_id}/security-events")
async def cloudflare_security_events(zone_id: str, hours: int = 1, limit: int = 50, user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    zone_id=validate_cloudflare_id(zone_id)
    _, client = await cf_client_for_user(user, db)
    try:
        return await client.security_events(zone_id, hours=hours, limit=limit)
    except CloudflareError as exc:
        raise HTTPException(502, str(exc))

@router.get("/cloudflare/zones/{zone_id}/security")
async def cloudflare_security(zone_id: str, scan_id: uuid.UUID | None = None, user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    zone_id=validate_cloudflare_id(zone_id)
    _, client = await cf_client_for_user(user, db)
    try:
        posture = await client.security_posture(zone_id)
    except CloudflareError as exc:
        raise HTTPException(502, str(exc))
    if scan_id:
        scan = await db.get(Scan, scan_id)
        if not scan or (scan.requested_by != user.id and user.role != Role.ADMIN):
            raise HTTPException(404, "Scan not found")
        events = (await db.execute(select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.created_at.desc()))).scalars().all()
        observed = None
        for event in events:
            candidate = (event.event_metadata or {}).get("modules", {}).get("http") if isinstance(event.event_metadata, dict) else None
            if candidate:
                observed = candidate
                break
        if observed:
            headers = {k.lower(): v for k, v in (observed.get("headers") or {}).items()}
            posture["observed_vs_cloudflare"] = {
                "https_observed": str(observed.get("url", "")).startswith("https://"),
                "hsts_header_observed": "strict-transport-security" in headers,
                "always_use_https_configured": posture["posture"].get("always_use_https"),
                "ssl_mode": posture["posture"].get("ssl_mode"),
                "min_tls_version": posture["posture"].get("min_tls_version"),
                "waf_ruleset_count": posture["posture"].get("waf_ruleset_count"),
            }
    return posture

@router.post("/ai/analyze/{scan_id}", response_model=AIAnalysisOut)
async def ai_analyze(scan_id: uuid.UUID, request: Request, user=Depends(require_roles(Role.ADMIN, Role.ANALYST)), db: AsyncSession = Depends(get_db)):
    if not await rate_limit(f"rl:ai:{user.id}", 30, 3600):
        raise HTTPException(429, "AI analysis rate limit exceeded")
    scan = await db.get(Scan, scan_id)
    if not scan or (scan.requested_by != user.id and user.role != Role.ADMIN):
        raise HTTPException(404, "Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(409, "Scan must be completed before AI analysis")
    findings = (await db.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars().all()
    evidence = {
        "target": (await db.get(Target, scan.target_id)).root_domain,
        "finding_count": len(findings),
        "findings": [{"title": f.title, "severity": f.severity.value, "confidence": f.confidence.value, "evidence": f.evidence, "affected_url": f.affected_url} for f in findings],
    }
    analysis = AIAnalysis(scan_id=scan.id, provider="cloudflare-workers-ai", model=settings.cloudflare_ai_model, status="QUEUED", input_evidence=evidence)
    db.add(analysis)
    await db.flush()
    await audit(db, user.id, "ai_analysis", "scan", scan.id, request.client.host if request.client else None)
    await db.commit()
    await enqueue(QUEUE_AI, {"analysis_id": str(analysis.id)})
    await db.refresh(analysis)
    return analysis

@router.get("/ai/analyze/{scan_id}/latest", response_model=AIAnalysisOut)
async def ai_latest(scan_id: uuid.UUID, user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    scan = await db.get(Scan, scan_id)
    if not scan or (scan.requested_by != user.id and user.role != Role.ADMIN):
        raise HTTPException(404, "Scan not found")
    analysis = (await db.execute(select(AIAnalysis).where(AIAnalysis.scan_id == scan_id).order_by(AIAnalysis.created_at.desc()).limit(1))).scalar_one_or_none()
    if not analysis:
        raise HTTPException(404, "No AI analysis")
    return analysis

@router.post("/reports/{scan_id}/generate")
async def generate_report(scan_id: uuid.UUID, request: Request, format: str = "json", user=Depends(require_roles(Role.ADMIN, Role.ANALYST)), db: AsyncSession = Depends(get_db)):
    if not await rate_limit(f"rl:report:{user.id}", 20, 3600):
        raise HTTPException(429, "Report generation rate limit exceeded")
    if format not in {"json", "csv", "html", "pdf"}:
        raise HTTPException(400, "Unsupported report format")
    scan = await db.get(Scan, scan_id)
    if not scan or (scan.requested_by != user.id and user.role != Role.ADMIN):
        raise HTTPException(404, "Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(409, "Scan must be completed before report generation")
    report = Report(scan_id=scan_id, format=format, status="QUEUED", created_by=user.id)
    db.add(report)
    await db.flush()
    await audit(db, user.id, "report_generate", "scan", scan_id, request.client.host if request.client else None, {"format": format})
    await db.commit()
    await enqueue(QUEUE_REPORT, {"report_id": str(report.id)})
    return {"report_id": str(report.id), "status": "QUEUED"}

@router.get("/reports/{scan_id}")
async def get_report(scan_id: uuid.UUID, format: str = "json", user=Depends(current_user), db: AsyncSession = Depends(get_db)):
    report = (await db.execute(select(Report).where(Report.scan_id == scan_id, Report.format == format).order_by(Report.created_at.desc()).limit(1))).scalar_one_or_none()
    if not report:
        raise HTTPException(404, "Report not generated")
    if report.created_by != user.id and user.role != Role.ADMIN:
        raise HTTPException(403, "Forbidden")
    if report.status != "COMPLETED":
        return {"status": report.status, "report_id": str(report.id), "error": report.content if report.status == "FAILED" else None}
    if format == "pdf":
        return Response(content=report.blob or b"", media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="cybersentinel-{scan_id}.pdf"'})
    return PlainTextResponse(report.content or "", media_type={"json": "application/json", "csv": "text/csv", "html": "text/html"}[format])

@router.get("/admin/users")
async def admin_users(user=Depends(require_roles(Role.ADMIN)), db: AsyncSession = Depends(get_db)):
    users = (await db.execute(select(User).order_by(User.created_at.desc()))).scalars().all()
    return [{"id": str(u.id), "email": u.email, "name": u.name, "role": u.role.value, "active": u.is_active, "created_at": u.created_at.isoformat()} for u in users]

@router.patch("/admin/users/{user_id}")
async def admin_update_user(user_id: uuid.UUID, data: AdminUserUpdate, request: Request, admin=Depends(require_roles(Role.ADMIN)), db: AsyncSession = Depends(get_db)):
    target=await db.get(User,user_id)
    if not target: raise HTTPException(404,"User not found")
    if "role" in data:
        try: target.role=Role(str(data["role"]).upper())
        except ValueError: raise HTTPException(400,"Invalid role")
    if "is_active" in data:
        if not isinstance(data["is_active"],bool): raise HTTPException(400,"is_active must be boolean")
        if target.id==admin.id and data["is_active"] is False: raise HTTPException(400,"Admin cannot disable the current account")
        target.is_active=data["is_active"]
    await audit(db,admin.id,"admin_user_update","user",target.id,request.client.host if request.client else None,{"role":target.role.value,"is_active":target.is_active})
    await db.commit(); await db.refresh(target)
    return {"id":str(target.id),"email":target.email,"name":target.name,"role":target.role.value,"active":target.is_active}

@router.get("/admin/audit-logs")
async def admin_audit(user=Depends(require_roles(Role.ADMIN)), db: AsyncSession = Depends(get_db)):
    logs = (await db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(500))).scalars().all()
    return [{"id": str(x.id), "action": x.action, "resource_type": x.resource_type, "resource_id": x.resource_id, "created_at": x.created_at.isoformat(), "details": x.details} for x in logs]

@router.get("/admin/system")
async def admin_system(user=Depends(require_roles(Role.ADMIN)), db: AsyncSession = Depends(get_db)):
    counts = {}
    for label, model in (("users", User), ("targets", Target), ("scans", Scan), ("findings", Finding), ("cloudflare_connections", CloudflareConnection), ("ai_analyses", AIAnalysis), ("audit_logs", AuditLog)):
        counts[label] = int((await db.execute(select(func.count()).select_from(model))).scalar_one())
    return {"api": True, "postgres": await ping_db(), "redis": await redis_ping(), "workers": await worker_statuses(), "counts": counts}

@router.get("/health")
async def health():
    return {"status": "ok", "service": "api"}

@router.get("/ready")
async def ready():
    db_ok = await ping_db()
    redis_ok = await redis_ping()
    if not (db_ok and redis_ok):
        raise HTTPException(503, {"postgres": db_ok, "redis": redis_ok})
    return {"status": "ready", "postgres": True, "redis": True}
