from __future__ import annotations
from datetime import datetime, timedelta, timezone
import hashlib, secrets
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet
from fastapi import HTTPException, status
from .config import get_settings

pwd_hasher = PasswordHasher()
settings = get_settings()
fernet = Fernet(settings.encryption_key.encode())


def hash_password(password: str) -> str:
    return pwd_hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return pwd_hasher.verify(hashed, password)
    except VerifyMismatchError:
        return False


def create_access_token(user_id: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": user_id, "role": role, "type": "access", "iat": now, "exp": now + timedelta(minutes=settings.jwt_access_minutes)}, settings.jwt_secret, algorithm="HS256")


def create_refresh_token(user_id: str, session_id: str) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": user_id, "sid": session_id, "jti": secrets.token_urlsafe(24), "type": "refresh", "iat": now, "exp": now + timedelta(days=settings.jwt_refresh_days)}, settings.jwt_secret, algorithm="HS256")


def decode_token(token: str, expected_type: str) -> dict:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    if payload.get("type") != expected_type or not payload.get("sub"):
        raise HTTPException(status_code=401, detail="Invalid token type")
    return payload


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def new_session_token_hash() -> str:
    return hash_token(secrets.token_urlsafe(48))


def encrypt_secret(value: str) -> str:
    return fernet.encrypt(value.encode()).decode()


def decrypt_secret(value: str) -> str:
    return fernet.decrypt(value.encode()).decode()
