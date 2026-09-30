import os
from typing import Optional
from fastapi import FastAPI, Depends, UploadFile, File, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.db.database import engine, Base, get_db
from backend.db.models import User
from backend.api.v1 import (
    auth as auth_v1,
    files as files_v1,
    security as security_v1,
    admin as admin_v1,
    dashboard as dashboard_v1,
    reports as reports_v1
)
from backend.schemas.auth_schemas import UserRegisterRequest, UserLoginRequest
from backend.services.auth_service import register_user, authenticate_user, get_current_user
from backend.services.file_service import process_file_encryption, process_file_decryption
from backend.services.threat_service import get_user_threat_status, simulate_attack_event, reset_user_simulation
from backend.services.audit_service import fetch_security_logs
from backend.api.v1.dashboard import get_dashboard_stats

# Ensure database tables exist for dev mode
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AI Hybrid File Encryption & Threat Detection System",
    description="Production-grade cybersecurity system combining AES-256-GCM, RSA-2048 OAEP, SHA-256 integrity, and Isolation Forest ML anomaly detection.",
    version="2.0.0"
)

# Configure CORS
origins = [origin.strip() for origin in settings.CORS_ORIGINS.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Versioned API v1 Routers
app.include_router(auth_v1.router, prefix="/api/v1")
app.include_router(files_v1.router, prefix="/api/v1")
app.include_router(security_v1.router, prefix="/api/v1")
app.include_router(admin_v1.router, prefix="/api/v1")
app.include_router(dashboard_v1.router, prefix="/api/v1")
app.include_router(reports_v1.router, prefix="/api/v1")

# ------------------------------------------------------------------
# Legacy Backward-Compatibility Route Aliases for Frontend SPA UI
# ------------------------------------------------------------------

@app.post("/api/auth/register", tags=["Legacy Frontend Aliases"])
def legacy_register(req: UserRegisterRequest, db: Session = Depends(get_db)):
    return register_user(db, username=req.username, email=req.email, password=req.password)

@app.post("/api/auth/login", tags=["Legacy Frontend Aliases"])
def legacy_login(req: UserLoginRequest, db: Session = Depends(get_db)):
    result = authenticate_user(db, username=req.username, password=req.password)
    return {"access_token": result["access_token"], "token_type": "bearer"}

@app.get("/api/auth/me", tags=["Legacy Frontend Aliases"])
def legacy_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/api/encrypt", tags=["Legacy Frontend Aliases"])
async def legacy_encrypt(file: UploadFile = File(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    file_bytes = await file.read()
    return process_file_encryption(db, current_user, file_bytes, file.filename)

@app.get("/api/files", tags=["Legacy Frontend Aliases"])
def legacy_files(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return files_v1.list_files(current_user=current_user, db=db)

@app.post("/api/decrypt/{file_id}", tags=["Legacy Frontend Aliases"])
def legacy_decrypt(file_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return process_file_decryption(db, current_user, file_id)

@app.get("/api/threat-detection/status", tags=["Legacy Frontend Aliases"])
def legacy_threat_status(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return get_user_threat_status(db, current_user)

@app.post("/api/ai/simulate-attack", tags=["Legacy Frontend Aliases"])
def legacy_simulate_attack(attack_type: str = Query("brute_force"), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return simulate_attack_event(db, current_user, attack_type)

@app.post("/api/ai/reset-simulation", tags=["Legacy Frontend Aliases"])
def legacy_reset_simulation(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return reset_user_simulation(db, current_user)

@app.get("/api/logs", tags=["Legacy Frontend Aliases"])
def legacy_logs(threat_level: str = Query("All"), search: str = Query(None), limit: int = Query(50), db: Session = Depends(get_db)):
    return fetch_security_logs(db, threat_level=threat_level, search=search, limit=limit)

@app.get("/api/dashboard/stats", tags=["Legacy Frontend Aliases"])
def legacy_dashboard_stats(db: Session = Depends(get_db)):
    return get_dashboard_stats(db)

@app.get("/api/reports/user-activity", tags=["Legacy Frontend Aliases"])
def legacy_download_user_report(
    format: str = Query("pdf"),
    token: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    user = reports_v1.resolve_report_user(db=db, auth_header=authorization, token=token, username=username)
    return reports_v1.download_user_activity_report(format=format, current_user=user, db=db)

# Static Files & Frontend SPA Server
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")
    app.mount("/css", StaticFiles(directory=os.path.join(frontend_dir, "css")), name="css")
    app.mount("/js", StaticFiles(directory=os.path.join(frontend_dir, "js")), name="js")

    @app.get("/")
    def serve_frontend_root():
        return FileResponse(os.path.join(frontend_dir, "index.html"))
