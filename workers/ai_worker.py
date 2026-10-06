from __future__ import annotations
import asyncio, os, logging
from datetime import datetime, timezone
from sqlalchemy import select
from app.db.database import SessionLocal
from app.models.all import AIAnalysis, Scan
from app.core.logging import configure_json_logging
from app.services.queue import dequeue, QUEUE_AI, set_worker_heartbeat
from app.services.ai import CloudflareWorkersAIProvider

configure_json_logging(os.getenv("LOG_LEVEL","INFO"))
async def process(job):
    aid=job["analysis_id"]
    async with SessionLocal() as db: a=await db.get(AIAnalysis,aid); evidence=a.input_evidence if a else None
    if not a or a.status=="COMPLETED": return
    try:
        a.status="RUNNING"
        async with SessionLocal() as db:
            a=await db.get(AIAnalysis,aid); a.status="RUNNING"; await db.commit()
        out=await CloudflareWorkersAIProvider().analyze(evidence)
        async with SessionLocal() as db:
            a=await db.get(AIAnalysis,aid); a.status="COMPLETED"; a.output=out; a.confidence=float(out.get("confidence",0) or 0); await db.commit()
    except Exception as exc:
        logging.exception("AI failed %s",aid)
        async with SessionLocal() as db:
            a=await db.get(AIAnalysis,aid); a.status="FAILED"; a.error=str(exc)[:4000]; await db.commit()
async def main():
    while True:
        try:
            await set_worker_heartbeat("ai")
            job=await dequeue(QUEUE_AI,5)
            if job: await process(job)
            await asyncio.sleep(.2)
        except Exception as exc:
            logging.error("ai worker dependency error: %s",exc)
            await asyncio.sleep(5)
if __name__=="__main__": asyncio.run(main())
