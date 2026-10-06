from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_session_factory = None


def _async_database_url(url: str) -> str:
    """Normalize Railway/Postgres URLs for SQLAlchemy's asyncpg driver."""
    parsed = urlsplit(url)
    scheme = parsed.scheme
    if scheme in {"postgres", "postgresql"}:
        scheme = "postgresql+asyncpg"
    elif scheme != "postgresql+asyncpg":
        raise ValueError("DATABASE_URL must use postgres://, postgresql://, or postgresql+asyncpg://")
    return urlunsplit((scheme, parsed.netloc, parsed.path, parsed.query, parsed.fragment))


def get_engine():
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            _async_database_url(get_settings().database_url),
            pool_pre_ping=True,
            pool_recycle=1800,
        )
    return _engine


def get_session_factory():
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(get_engine(), expire_on_commit=False, class_=AsyncSession)
    return _session_factory


class LazySessionFactory:
    def __call__(self):
        return get_session_factory()()


SessionLocal = LazySessionFactory()


async def get_db():
    async with get_session_factory()() as session:
        yield session


async def ping_db() -> bool:
    try:
        from sqlalchemy import text

        async with get_engine().connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
