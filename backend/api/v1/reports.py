from typing import Optional
from fastapi import APIRouter, Depends, Query, Header, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.db.database import get_db
from backend.db.models.user import User
from backend.core.security import decode_access_token
from backend.services.audit_service import (
    build_user_activity_report,
    generate_user_report_csv,
    generate_user_report_pdf,
    generate_user_report_html
)

router = APIRouter(prefix="/reports", tags=["User Activity & Audit Reports"])

def resolve_report_user(
    db: Session = Depends(get_db),
    auth_header: Optional[str] = Header(None, alias="Authorization"),
    token: Optional[str] = Query(None),
    username: Optional[str] = Query(None)
) -> User:
    """
    Resolve target user for report generation using:
    1. Authorization Bearer header
    2. ?token= query parameter
    3. ?username= query parameter
    4. Active session fallback to most recently active user
    """
    raw_token = None
    if auth_header and auth_header.startswith("Bearer "):
        raw_token = auth_header.split(" ", 1)[1].strip()
    elif token:
        raw_token = token.strip()

    if raw_token:
        payload = decode_access_token(raw_token)
        if payload and payload.get("sub"):
            user = db.query(User).filter(User.username == payload.get("sub")).first()
            if user:
                return user

    if username:
        user = db.query(User).filter(User.username == username).first()
        if user:
            return user

    # Fallback to the latest active user in the system
    user = db.query(User).order_by(desc(User.last_login_at)).first()
    if not user:
        user = db.query(User).first()

    if user:
        return user

    raise HTTPException(status_code=401, detail="No user found to generate report")

@router.get("/user-activity")
def download_user_activity_report(
    format: str = Query("pdf", description="Export format: pdf, csv, html, or json"),
    current_user: User = Depends(resolve_report_user),
    db: Session = Depends(get_db)
):
    """
    Download or view a complete security audit report of all activities
    performed by the user. Supports PDF, CSV, HTML, and JSON.
    """
    report_data = build_user_activity_report(db, current_user)
    username = current_user.username.replace(" ", "_")
    fmt = format.lower().strip()

    if fmt == "csv":
        csv_data = generate_user_report_csv(report_data)
        filename = f"activity_report_{username}.csv"
        return Response(
            content=csv_data.encode("utf-8"),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )

    elif fmt == "html":
        html_data = generate_user_report_html(report_data)
        return HTMLResponse(content=html_data)

    elif fmt == "json":
        return JSONResponse(content=report_data)

    else:  # default to pdf
        pdf_bytes = generate_user_report_pdf(report_data)
        filename = f"activity_report_{username}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )

@router.get("/user-activity/preview")
def preview_user_activity(
    current_user: User = Depends(resolve_report_user),
    db: Session = Depends(get_db)
):
    """Get high-level summary of user activity for dashboard display."""
    report_data = build_user_activity_report(db, current_user)
    return report_data
