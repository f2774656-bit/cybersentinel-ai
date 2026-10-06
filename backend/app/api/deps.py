from __future__ import annotations
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.security import decode_token
from app.db.database import get_db
from app.models.all import User, Role

bearer=HTTPBearer(auto_error=False)

async def current_user(request: Request, creds: HTTPAuthorizationCredentials=Depends(bearer), db: AsyncSession=Depends(get_db)) -> User:
    token=creds.credentials if creds else request.cookies.get("access_token")
    if not token: raise HTTPException(401,"Authentication required")
    payload=decode_token(token,"access")
    user=await db.get(User,payload["sub"])
    if not user or not user.is_active: raise HTTPException(401,"User inactive or missing")
    return user

def require_roles(*roles: Role):
    async def dep(user: User=Depends(current_user)):
        if user.role not in roles: raise HTTPException(403,"Insufficient permissions")
        return user
    return dep
