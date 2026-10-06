from __future__ import annotations
import asyncio, os, logging
from datetime import datetime, timezone
from sqlalchemy import select
from app.db.database import SessionLocal
from app.models.all import Scan, ScanModule, ScanEvent, ScanStatus, Finding, FindingEvidence, Severity, Confidence, Target
from app.core.logging import configure_json_logging
from app.services.queue import dequeue, QUEUE_SCAN, QUEUE_AI, set_worker_heartbeat, enqueue
from app.services.scoring import calculate_score
from scanner.engine import run_scan

configure_json_logging(os.getenv("LOG_LEVEL","INFO"))

async def process(job):
    sid=job["scan_id"]
    async with SessionLocal() as db:
        scan=await db.get(Scan,sid)
        if not scan or scan.status in {ScanStatus.CANCELLED,ScanStatus.COMPLETED}: return
        target=await db.get(Target,scan.target_id)
        if not target: scan.status=ScanStatus.FAILED; scan.error="Target deleted"; await db.commit(); return
        root_domain=target.root_domain
        scan.status=ScanStatus.VALIDATING; await db.flush(); db.add(ScanEvent(scan_id=scan.id,event_type="scan",message="Scope validation started")); await db.commit()
    async def emit(module,status):
        async with SessionLocal() as db:
            scan=await db.get(Scan,sid)
            if not scan: return
            scan.current_module=module
            if status=="RUNNING":
                scan.status=ScanStatus.RUNNING; db.add(ScanModule(scan_id=scan.id,name=module,status="RUNNING",started_at=datetime.now(timezone.utc)))
            else:
                mod=(await db.execute(select(ScanModule).where(ScanModule.scan_id==sid,ScanModule.name==module).order_by(ScanModule.started_at.desc()).limit(1))).scalar_one_or_none()
                if mod: mod.status=status; mod.ended_at=datetime.now(timezone.utc)
                scan.modules_completed+=1
            db.add(ScanEvent(scan_id=scan.id,event_type="module",message=f"{module}: {status}",metadata={"module":module,"status":status})); await db.commit()
    try:
        async with SessionLocal() as db:
            scan=await db.get(Scan,sid); scan.started_at=datetime.now(timezone.utc); await db.commit()
        async with SessionLocal() as db:
            scan=await db.get(Scan,sid); root_domain= (await db.get(Target,scan.target_id)).root_domain; snapshot=scan.scope_snapshot; profile=scan.profile
        data,findings=await run_scan(root_domain,snapshot,profile,emit)
        async with SessionLocal() as db:
            scan=await db.get(Scan,sid)
            for f in findings:
                row=Finding(scan_id=scan.id,**{k:(Severity[v] if k=="severity" else Confidence[v] if k=="confidence" else val) for k,val in f.items()})
                db.add(row)
                await db.flush()
                db.add(FindingEvidence(finding_id=row.id,kind=f["category"],source="scanner",content=f["evidence"]))
            await db.flush(); fs=(await db.execute(select(Finding).where(Finding.scan_id==sid))).scalars().all(); scan.final_score=calculate_score(fs); scan.status=ScanStatus.COMPLETED; scan.ended_at=datetime.now(timezone.utc); scan.current_module=None; db.add(ScanEvent(scan_id=scan.id,event_type="scan",message=f"Scan completed with score {scan.final_score}",metadata={"modules":data})); await db.commit()
    except Exception as exc:
        logging.exception("scan failed %s",sid)
        async with SessionLocal() as db:
            scan=await db.get(Scan,sid)
            if scan: scan.status=ScanStatus.FAILED; scan.ended_at=datetime.now(timezone.utc); scan.error=str(exc)[:4000]; db.add(ScanEvent(scan_id=scan.id,event_type="error",level="ERROR",message="Scan failed")); await db.commit()

async def main():
    while True:
        try:
            await set_worker_heartbeat("scanner")
            job=await dequeue(QUEUE_SCAN,timeout=5)
            if job: await process(job)
            await asyncio.sleep(0.2)
        except Exception as exc:
            logging.error("scanner worker dependency error: %s",exc)
            await asyncio.sleep(5)
if __name__=="__main__": asyncio.run(main())
