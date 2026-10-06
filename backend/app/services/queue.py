from __future__ import annotations
import json
from app.core.config import get_settings

settings=get_settings()
QUEUE_SCAN="csai:queue:scan"; QUEUE_AI="csai:queue:ai"; QUEUE_REPORT="csai:queue:report"

def redis():
    from redis.asyncio import Redis
    return Redis.from_url(settings.redis_url, decode_responses=True)

async def enqueue(queue: str, payload: dict):
    r=redis()
    try: await r.lpush(queue,json.dumps(payload))
    finally: await r.aclose()

async def dequeue(queue: str, timeout=5):
    r=redis()
    try:
        item=await r.brpop(queue,timeout=timeout)
        return json.loads(item[1]) if item else None
    finally: await r.aclose()

async def redis_ping()->bool:
    try: r=redis()
    except Exception: return False
    try: return bool(await r.ping())
    except Exception: return False
    finally: await r.aclose()

async def set_worker_heartbeat(name):
    r=redis()
    try: await r.set(f"csai:worker:{name}","online",ex=45)
    finally: await r.aclose()

async def worker_statuses(names=("scanner","ai","report")):
    r=redis()
    try:
        values=await r.mget([f"csai:worker:{n}" for n in names])
        return {n:(v=="online") for n,v in zip(names,values)}
    except Exception:
        return {n:False for n in names}
    finally: await r.aclose()
