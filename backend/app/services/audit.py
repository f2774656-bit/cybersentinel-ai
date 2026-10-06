from sqlalchemy.ext.asyncio import AsyncSession
from app.models.all import AuditLog

async def audit(db: AsyncSession, user_id, action: str, resource_type=None, resource_id=None, ip_address=None, details=None):
    safe=dict(details or {})
    for k in list(safe):
        if any(x in k.lower() for x in ("token","password","secret","authorization","cookie")): safe.pop(k,None)
    db.add(AuditLog(user_id=user_id,action=action,resource_type=resource_type,resource_id=str(resource_id) if resource_id else None,ip_address=ip_address,details=safe))
