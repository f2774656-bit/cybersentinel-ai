from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api.routes import router
from app.core.config import get_settings
import logging, uuid
from app.core.logging import configure_json_logging

settings=get_settings(); configure_json_logging(settings.log_level)
app=FastAPI(title=settings.app_name,version="1.0.0",docs_url="/docs",redoc_url="/redoc")
origins=[x.strip() for x in settings.cors_origins.split(",") if x.strip()]
app.add_middleware(CORSMiddleware,allow_origins=origins,allow_credentials=False,allow_methods=["GET","POST","PATCH","DELETE","OPTIONS"],allow_headers=["Authorization","Content-Type","X-Request-ID"])

@app.middleware("http")
async def security_headers(request:Request,call_next):
    rid=request.headers.get("X-Request-ID") or str(uuid.uuid4())
    response=await call_next(request); response.headers["X-Request-ID"]=rid; response.headers["X-Content-Type-Options"]="nosniff"; response.headers["X-Frame-Options"]="DENY"; response.headers["Referrer-Policy"]="no-referrer"; response.headers["Permissions-Policy"]="camera=(),microphone=(),geolocation=()"; response.headers["Cache-Control"]="no-store" if request.url.path.startswith("/api/auth") else response.headers.get("Cache-Control","")
    return response


@app.exception_handler(HTTPException)
async def http_error(request:Request,exc:HTTPException):
    rid=request.headers.get("X-Request-ID",str(uuid.uuid4()))
    detail=exc.detail if isinstance(exc.detail,str) else "Request rejected"
    return JSONResponse(status_code=exc.status_code,content={"code":f"HTTP_{exc.status_code}","message":detail,"request_id":rid})

@app.exception_handler(RequestValidationError)
async def validation_error(request:Request,exc:RequestValidationError):
    rid=request.headers.get("X-Request-ID",str(uuid.uuid4()))
    return JSONResponse(status_code=422,content={"code":"VALIDATION_ERROR","message":"Request validation failed","request_id":rid,"errors":exc.errors()})

@app.exception_handler(Exception)
async def unhandled(request:Request,exc:Exception):
    rid=request.headers.get("X-Request-ID",str(uuid.uuid4())); logging.exception("request_id=%s",rid); return JSONResponse(status_code=500,content={"code":"INTERNAL_ERROR","message":"Internal server error","request_id":rid})

app.include_router(router)
@app.get("/")
async def root(): return {"name":settings.app_name,"version":"1.0.0","docs":"/docs"}

@app.get("/health")
async def root_health(): return {"status":"ok","service":"api"}

@app.get("/ready")
async def root_ready():
    from app.db.database import ping_db
    from app.services.queue import redis_ping
    db_ok=await ping_db(); redis_ok=await redis_ping()
    if not (db_ok and redis_ok):
        from fastapi import HTTPException
        raise HTTPException(503,{"postgres":db_ok,"redis":redis_ok})
    return {"status":"ready","postgres":True,"redis":True}
