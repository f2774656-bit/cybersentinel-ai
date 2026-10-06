from __future__ import annotations
import asyncio, logging, os
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from app.db.database import SessionLocal
from app.models.all import Report, Scan, Finding, AIAnalysis, CloudflareConnection
from app.core.security import decrypt_secret
from app.services.cloudflare import CloudflareClient
from app.core.logging import configure_json_logging
from app.services.queue import dequeue, QUEUE_REPORT, set_worker_heartbeat
from app.services.reports import build_report

configure_json_logging(os.getenv("LOG_LEVEL","INFO"))
async def process(job):
    rid=job["report_id"]
    async with SessionLocal() as db:
        r=await db.get(Report,rid); s=(await db.execute(select(Scan).options(selectinload(Scan.target),selectinload(Scan.events)).where(Scan.id==r.scan_id))).scalar_one_or_none() if r else None
        if not r or not s: return
    try:
        async with SessionLocal() as db:
            r=await db.get(Report,rid); r.status="RUNNING"; await db.commit()
            s=(await db.execute(select(Scan).options(selectinload(Scan.target),selectinload(Scan.events)).where(Scan.id==r.scan_id))).scalar_one(); finds=(await db.execute(select(Finding).where(Finding.scan_id==s.id))).scalars().all(); a=(await db.execute(select(AIAnalysis).where(AIAnalysis.scan_id==s.id).order_by(AIAnalysis.created_at.desc()).limit(1))).scalar_one_or_none(); ai=a.output if a and a.status=="COMPLETED" else None; fmt=r.format; cf=None
            conn=(await db.execute(select(CloudflareConnection).where(CloudflareConnection.user_id==r.created_by).order_by(CloudflareConnection.created_at.desc()).limit(1))).scalar_one_or_none()
            if conn and conn.zone_id:
                try: cf=await CloudflareClient(decrypt_secret(conn.token_encrypted)).security_posture(conn.zone_id)
                except Exception: cf=None
        content=build_report(s,finds,ai,fmt,cf)
        async with SessionLocal() as db:
            r=await db.get(Report,rid); r.status="COMPLETED"
            if r.format=="pdf": r.blob=content
            else: r.content=content
            await db.commit()
    except Exception as exc:
        logging.exception("report failed %s",rid)
        async with SessionLocal() as db:
            r=await db.get(Report,rid); r.status="FAILED"; r.content=str(exc)[:4000]; await db.commit()
async def main():
    while True:
        try:
            await set_worker_heartbeat("report")
            job=await dequeue(QUEUE_REPORT,5)
            if job: await process(job)
            await asyncio.sleep(.2)
        except Exception as exc:
            logging.error("report worker dependency error: %s",exc)
            await asyncio.sleep(5)
if __name__=="__main__": asyncio.run(main())
