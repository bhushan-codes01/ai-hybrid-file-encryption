import datetime
import io
import csv
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

from backend.db.models.security_event import SecurityLog
from backend.db.models.user import User
from backend.db.models.activity import UserActivity
from backend.db.models.file import FileRecord
from backend.services.threat_service import get_user_threat_status

def fetch_security_logs(
    db: Session,
    threat_level: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50
) -> List[SecurityLog]:
    """Retrieve security audit logs with filtering by threat level and search query."""
    query = db.query(SecurityLog)

    if threat_level and threat_level != "All":
        query = query.filter(SecurityLog.threat_level == threat_level)

    if search:
        pattern = f"%{search}%"
        query = query.filter(
            (SecurityLog.username.like(pattern)) |
            (SecurityLog.activity_type.like(pattern)) |
            (SecurityLog.details.like(pattern))
        )

    return query.order_by(desc(SecurityLog.timestamp)).limit(limit).all()

def format_bytes(size: int) -> str:
    """Format file size in bytes to human-readable format."""
    if size < 1024:
        return f"{size} B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.2f} KB"
    else:
        return f"{size / (1024 * 1024):.2f} MB"

def build_user_activity_report(db: Session, target_user: User) -> Dict[str, Any]:
    """
    Compile comprehensive activity history, telemetry, files, and threat analytics
    for a given user.
    """
    # 1. User Activity Telemetry
    activity = db.query(UserActivity).filter(UserActivity.user_id == target_user.id).first()
    if not activity:
        activity = UserActivity(user_id=target_user.id)
        db.add(activity)
        db.commit()

    threat_info = get_user_threat_status(db, target_user)

    # 2. Files Encrypted by User
    files = db.query(FileRecord).filter(FileRecord.user_id == target_user.id).order_by(desc(FileRecord.encryption_timestamp)).all()
    files_data = [
        {
            "id": f.id,
            "filename": f.original_filename,
            "size_bytes": f.file_size or 0,
            "size_formatted": format_bytes(f.file_size or 0),
            "encryption_algorithm": f.encryption_algorithm or "AES-256-GCM",
            "key_algorithm": f.key_algorithm or "RSA-2048-OAEP",
            "sha256_hash": f.sha256_hash or "",
            "timestamp": f.encryption_timestamp.strftime("%Y-%m-%d %H:%M:%S") if f.encryption_timestamp else "N/A"
        }
        for f in files
    ]

    # 3. Security Event Logs for User
    logs = (
        db.query(SecurityLog)
        .filter((SecurityLog.user_id == target_user.id) | (SecurityLog.username == target_user.username))
        .order_by(desc(SecurityLog.timestamp))
        .all()
    )

    logs_data = [
        {
            "id": l.id,
            "timestamp": l.timestamp.strftime("%Y-%m-%d %H:%M:%S") if l.timestamp else "N/A",
            "activity_type": l.activity_type,
            "status": l.status,
            "threat_level": l.threat_level,
            "anomaly_score": round(float(l.anomaly_score or 0.0), 4),
            "details": l.details or ""
        }
        for l in logs
    ]

    total_vault_bytes = sum(f.file_size or 0 for f in files)

    # Breakdown of events
    threat_breakdown = {"Low": 0, "Medium": 0, "High": 0}
    for l in logs:
        tl = l.threat_level if l.threat_level in threat_breakdown else "Low"
        threat_breakdown[tl] += 1

    return {
        "generated_at": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "user": {
            "id": target_user.id,
            "username": target_user.username,
            "email": target_user.email,
            "role": target_user.role,
            "is_active": target_user.is_active,
            "created_at": target_user.created_at.strftime("%Y-%m-%d %H:%M:%S") if target_user.created_at else "N/A",
            "last_login_at": target_user.last_login_at.strftime("%Y-%m-%d %H:%M:%S") if target_user.last_login_at else "N/A"
        },
        "telemetry": {
            "login_attempts": activity.login_attempts or 0,
            "failed_logins": activity.failed_logins or 0,
            "encryption_requests": activity.encryption_requests or 0,
            "decryption_requests": activity.decryption_requests or 0,
            "failed_decryptions": activity.failed_decryptions or 0,
            "last_access": activity.last_access_timestamp.strftime("%Y-%m-%d %H:%M:%S") if activity.last_access_timestamp else "N/A"
        },
        "ai_threat_evaluation": {
            "classification": threat_info.get("status", "NORMAL"),
            "threat_level": threat_info.get("threat_level", "Low"),
            "anomaly_score": threat_info.get("anomaly_score", 0.0),
            "access_frequency": threat_info.get("access_frequency", 1.0),
            "explanation": threat_info.get("explanation", "Standard user behavior pattern.")
        },
        "summary": {
            "total_files_encrypted": len(files),
            "total_vault_size": format_bytes(total_vault_bytes),
            "total_events_recorded": len(logs),
            "threat_breakdown": threat_breakdown
        },
        "files": files_data,
        "logs": logs_data
    }

def generate_user_report_csv(report_data: Dict[str, Any]) -> str:
    """Generate structured CSV export of user profile, metrics, files, and full audit logs."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Section 1: Header & Profile
    writer.writerow(["=== USER ACTIVITY & SECURITY AUDIT REPORT ==="])
    writer.writerow(["Generated At", report_data["generated_at"]])
    writer.writerow(["Username", report_data["user"]["username"]])
    writer.writerow(["User ID", report_data["user"]["id"]])
    writer.writerow(["Email", report_data["user"]["email"]])
    writer.writerow(["Role", report_data["user"]["role"]])
    writer.writerow(["Account Created", report_data["user"]["created_at"]])
    writer.writerow(["Last Login", report_data["user"]["last_login_at"]])
    writer.writerow([])

    # Section 2: AI Threat & Telemetry KPI Metrics
    writer.writerow(["=== AI THREAT & TELEMETRY METRICS ==="])
    writer.writerow(["Current AI Classification", report_data["ai_threat_evaluation"]["classification"]])
    writer.writerow(["Current Threat Level", report_data["ai_threat_evaluation"]["threat_level"]])
    writer.writerow(["Isolation Forest Anomaly Score", report_data["ai_threat_evaluation"]["anomaly_score"]])
    writer.writerow(["Access Frequency (req/min)", report_data["ai_threat_evaluation"]["access_frequency"]])
    writer.writerow(["Total Login Attempts", report_data["telemetry"]["login_attempts"]])
    writer.writerow(["Failed Login Attempts", report_data["telemetry"]["failed_logins"]])
    writer.writerow(["Encryption Requests", report_data["telemetry"]["encryption_requests"]])
    writer.writerow(["Decryption Requests", report_data["telemetry"]["decryption_requests"]])
    writer.writerow(["Failed Decryptions", report_data["telemetry"]["failed_decryptions"]])
    writer.writerow([])

    # Section 3: Files Encrypted
    writer.writerow(["=== ENCRYPTED FILES INVENTORY ==="])
    writer.writerow(["File ID", "Original Filename", "Size", "Encryption Algorithm", "Key Wrapping Algorithm", "SHA-256 Digest", "Timestamp"])
    for f in report_data["files"]:
        writer.writerow([
            f["id"],
            f["filename"],
            f["size_formatted"],
            f["encryption_algorithm"],
            f["key_algorithm"],
            f["sha256_hash"],
            f["timestamp"]
        ])
    writer.writerow([])

    # Section 4: Chronological Event Log
    writer.writerow(["=== COMPLETE CHRONOLOGICAL AUDIT TRAIL ==="])
    writer.writerow(["Log ID", "Timestamp", "Activity Type", "Status", "Threat Level", "Anomaly Score", "Details"])
    for l in report_data["logs"]:
        writer.writerow([
            l["id"],
            l["timestamp"],
            l["activity_type"],
            l["status"],
            l["threat_level"],
            l["anomaly_score"],
            l["details"]
        ])

    return output.getvalue()

def generate_user_report_pdf(report_data: Dict[str, Any]) -> bytes:
    """Generate high-aesthetic, professional cybersecurity PDF audit report using ReportLab."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=4
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=10
    )
    section_title = ParagraphStyle(
        'SectionTitle',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=15,
        textColor=colors.HexColor('#0284c7'),
        spaceBefore=12,
        spaceAfter=6
    )
    cell_bold = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#1e293b')
    )
    cell_normal = ParagraphStyle(
        'CellNormal',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.HexColor('#334155')
    )
    cell_header = ParagraphStyle(
        'CellHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.white
    )

    elements = []

    # Title & Metadata
    elements.append(Paragraph("CYBERVAULT | AI HYBRID FILE ENCRYPTION", title_style))
    elements.append(Paragraph(
        f"<b>USER SECURITY AUDIT & ACTIVITY REPORT</b> &nbsp;|&nbsp; Generated on: {report_data['generated_at']}",
        subtitle_style
    ))
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#06b6d4'), spaceAfter=10))

    # Profile & Threat Status Overview Table
    ai = report_data["ai_threat_evaluation"]
    u = report_data["user"]
    t = report_data["telemetry"]
    s = report_data["summary"]

    threat_color = colors.HexColor('#10b981')
    if ai['threat_level'] == 'Medium':
        threat_color = colors.HexColor('#f59e0b')
    elif ai['threat_level'] == 'High':
        threat_color = colors.HexColor('#ef4444')

    profile_data = [
        [
            Paragraph("<b>User Profile</b>", cell_bold),
            Paragraph(f"<b>Username:</b> {u['username']}<br/><b>Email:</b> {u['email']}<br/><b>Role:</b> {u['role']}<br/><b>Member Since:</b> {u['created_at']}", cell_normal),
            Paragraph("<b>AI Security Status</b>", cell_bold),
            Paragraph(
                f"<b>Threat Level:</b> <font color='{threat_color.hexval()}'><b>{ai['threat_level'].upper()}</b></font><br/>"
                f"<b>Classification:</b> {ai['classification']}<br/>"
                f"<b>Anomaly Score:</b> {ai['anomaly_score']}<br/>"
                f"<b>Access Rate:</b> {ai['access_frequency']} req/min",
                cell_normal
            )
        ],
        [
            Paragraph("<b>Telemetry Summary</b>", cell_bold),
            Paragraph(
                f"<b>Login Attempts:</b> {t['login_attempts']} (Failed: {t['failed_logins']})<br/>"
                f"<b>Encryption Reqs:</b> {t['encryption_requests']}<br/>"
                f"<b>Decryption Reqs:</b> {t['decryption_requests']} (Failed: {t['failed_decryptions']})",
                cell_normal
            ),
            Paragraph("<b>Vault Inventory</b>", cell_bold),
            Paragraph(
                f"<b>Files Encrypted:</b> {s['total_files_encrypted']}<br/>"
                f"<b>Total Storage:</b> {s['total_vault_size']}<br/>"
                f"<b>Total Audit Events:</b> {s['total_events_recorded']}<br/>"
                f"<b>Threat Alerts:</b> {s['threat_breakdown']['High']} High, {s['threat_breakdown']['Medium']} Med",
                cell_normal
            )
        ]
    ]

    t_profile = Table(profile_data, colWidths=[90, 180, 90, 180])
    t_profile.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(t_profile)
    elements.append(Spacer(1, 10))

    # Section 2: Encrypted Files Vault Inventory
    elements.append(Paragraph("Encrypted Files Inventory", section_title))
    if not report_data["files"]:
        elements.append(Paragraph("<i>No encrypted files currently found for this user.</i>", cell_normal))
    else:
        files_table_data = [
            [
                Paragraph("<b>Filename</b>", cell_header),
                Paragraph("<b>Size</b>", cell_header),
                Paragraph("<b>Algorithm</b>", cell_header),
                Paragraph("<b>SHA-256 Checksum</b>", cell_header),
                Paragraph("<b>Uploaded At</b>", cell_header)
            ]
        ]
        for f in report_data["files"]:
            files_table_data.append([
                Paragraph(f["filename"], cell_bold),
                Paragraph(f["size_formatted"], cell_normal),
                Paragraph(f"{f['encryption_algorithm']}<br/>+{f['key_algorithm']}", cell_normal),
                Paragraph(f"<font size=6>{f['sha256_hash'][:32]}...</font>", cell_normal),
                Paragraph(f["timestamp"], cell_normal)
            ])
        t_files = Table(files_table_data, colWidths=[120, 50, 100, 160, 110])
        t_files.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        elements.append(t_files)

    elements.append(Spacer(1, 10))

    # Section 3: Chronological Security Audit Events
    elements.append(Paragraph("Chronological Security & Activity Audit Trail", section_title))
    if not report_data["logs"]:
        elements.append(Paragraph("<i>No security event logs recorded yet.</i>", cell_normal))
    else:
        logs_table_data = [
            [
                Paragraph("<b>Timestamp</b>", cell_header),
                Paragraph("<b>Activity Type</b>", cell_header),
                Paragraph("<b>Status</b>", cell_header),
                Paragraph("<b>Threat</b>", cell_header),
                Paragraph("<b>Score</b>", cell_header),
                Paragraph("<b>Event Details</b>", cell_header)
            ]
        ]
        for l in report_data["logs"][:60]:  # Cap at latest 60 for clean PDF
            tl_color = '#10b981' if l['threat_level'] == 'Low' else ('#f59e0b' if l['threat_level'] == 'Medium' else '#ef4444')
            logs_table_data.append([
                Paragraph(l["timestamp"], cell_normal),
                Paragraph(f"<b>{l['activity_type']}</b>", cell_normal),
                Paragraph(l["status"], cell_normal),
                Paragraph(f"<font color='{tl_color}'><b>{l['threat_level']}</b></font>", cell_normal),
                Paragraph(str(l["anomaly_score"]), cell_normal),
                Paragraph(l["details"], cell_normal)
            ])
        t_logs = Table(logs_table_data, colWidths=[90, 110, 55, 50, 45, 190])
        t_logs.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f8fafc')]),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        elements.append(t_logs)

    # Footer note
    elements.append(Spacer(1, 15))
    elements.append(Paragraph(
        "<i>CONFIDENTIAL DOCUMENT - Generated automatically by AI-Driven Hybrid File Encryption System. Verifiable via SHA-256 integrity checks.</i>",
        subtitle_style
    ))

    doc.build(elements)
    return buffer.getvalue()

def generate_user_report_html(report_data: Dict[str, Any]) -> str:
    """Generate a responsive, dark-mode cybersecurity themed HTML report ready for printing/saving as PDF."""
    u = report_data["user"]
    t = report_data["telemetry"]
    ai = report_data["ai_threat_evaluation"]
    s = report_data["summary"]

    badge_color = "#10b981"
    if ai["threat_level"] == "Medium":
        badge_color = "#f59e0b"
    elif ai["threat_level"] == "High":
        badge_color = "#ef4444"

    files_rows = ""
    for f in report_data["files"]:
        files_rows += f"""
        <tr>
            <td style="font-weight: 600;">{f['filename']}</td>
            <td>{f['size_formatted']}</td>
            <td><code>{f['encryption_algorithm']}</code></td>
            <td><code>{f['key_algorithm']}</code></td>
            <td style="font-family: monospace; font-size: 0.75rem; word-break: break-all;">{f['sha256_hash']}</td>
            <td style="color: #64748b; font-size: 0.8rem;">{f['timestamp']}</td>
        </tr>
        """

    logs_rows = ""
    for l in report_data["logs"]:
        t_color = "#10b981" if l["threat_level"] == "Low" else ("#f59e0b" if l["threat_level"] == "Medium" else "#ef4444")
        status_color = "#10b981" if l["status"] == "SUCCESS" else "#ef4444"
        logs_rows += f"""
        <tr>
            <td style="color: #64748b; font-size: 0.8rem; white-space: nowrap;">{l['timestamp']}</td>
            <td style="font-weight: 600;">{l['activity_type']}</td>
            <td><span style="color: {status_color}; font-weight: 600;">{l['status']}</span></td>
            <td><span style="background: {t_color}22; color: {t_color}; border: 1px solid {t_color}; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700;">{l['threat_level']}</span></td>
            <td style="font-family: monospace;">{l['anomaly_score']}</td>
            <td style="font-size: 0.85rem; color: #94a3b8;">{l['details']}</td>
        </tr>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Security Audit Report - {u['username']}</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {{
            --bg: #090d16;
            --card: #111827;
            --border: #1e293b;
            --accent: #00f2fe;
            --text: #f8fafc;
            --muted: #94a3b8;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            padding: 2rem;
            line-height: 1.5;
        }}
        .report-container {{
            max-width: 1000px;
            margin: 0 auto;
            background: var(--card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 2.5rem;
            box-shadow: 0 20px 40px rgba(0,0,0,0.5);
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        .brand-title {{
            font-size: 1.6rem;
            font-weight: 800;
            color: #fff;
            letter-spacing: 0.05em;
        }}
        .brand-subtitle {{
            color: var(--accent);
            font-size: 0.85rem;
            letter-spacing: 0.1em;
            margin-top: 0.25rem;
        }}
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .kpi-card {{
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 1rem 1.25rem;
        }}
        .kpi-label {{
            font-size: 0.75rem;
            color: var(--muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.25rem;
        }}
        .kpi-value {{
            font-size: 1.4rem;
            font-weight: 700;
            color: #fff;
        }}
        .section-title {{
            font-size: 1.15rem;
            font-weight: 700;
            color: var(--accent);
            margin: 2rem 0 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            margin-bottom: 1.5rem;
        }}
        th {{
            background: rgba(255,255,255,0.05);
            text-align: left;
            padding: 0.75rem;
            color: #cbd5e1;
            border-bottom: 1px solid var(--border);
            font-weight: 600;
        }}
        td {{
            padding: 0.75rem;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }}
        .btn-print {{
            background: linear-gradient(135deg, #00f2fe, #4facfe);
            color: #050b14;
            border: none;
            padding: 0.6rem 1.2rem;
            border-radius: 6px;
            font-weight: 700;
            font-size: 0.85rem;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }}
        @media print {{
            body {{ background: #fff; color: #000; padding: 0; }}
            .report-container {{ border: none; box-shadow: none; padding: 0; background: #fff; color: #000; }}
            .btn-print {{ display: none !important; }}
            .kpi-card {{ border: 1px solid #ccc; }}
            .kpi-value {{ color: #000; }}
            th {{ background: #eee; color: #000; border-color: #ccc; }}
            td {{ border-color: #eee; color: #222; }}
            .section-title {{ color: #0284c7; }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <div class="header">
            <div>
                <div class="brand-title"><i class="fa-solid fa-shield-halved" style="color: var(--accent);"></i> CYBERVAULT</div>
                <div class="brand-subtitle">AI-POWERED HYBRID FILE ENCRYPTION & THREAT RADAR</div>
            </div>
            <div style="text-align: right;">
                <button class="btn-print" onclick="window.print()">
                    <i class="fa-solid fa-print"></i> Print / Save as PDF
                </button>
                <div style="font-size: 0.75rem; color: var(--muted); margin-top: 0.5rem;">
                    Generated: {report_data['generated_at']}
                </div>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-label">User Account</div>
                <div class="kpi-value">{u['username']}</div>
                <div style="font-size: 0.75rem; color: var(--muted);">{u['email']} ({u['role']})</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">AI Threat Level</div>
                <div class="kpi-value" style="color: {badge_color};">{ai['threat_level']}</div>
                <div style="font-size: 0.75rem; color: var(--muted);">Score: {ai['anomaly_score']}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Encrypted Files</div>
                <div class="kpi-value">{s['total_files_encrypted']}</div>
                <div style="font-size: 0.75rem; color: var(--muted);">Total: {s['total_vault_size']}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-label">Total Events Logged</div>
                <div class="kpi-value">{s['total_events_recorded']}</div>
                <div style="font-size: 0.75rem; color: var(--muted);">Failures: {t['failed_logins'] + t['failed_decryptions']}</div>
            </div>
        </div>

        <div class="section-title"><i class="fa-solid fa-vault"></i> Encrypted Files Vault Inventory</div>
        <table>
            <thead>
                <tr>
                    <th>Filename</th>
                    <th>Size</th>
                    <th>Encryption</th>
                    <th>Key Protection</th>
                    <th>SHA-256 Digest</th>
                    <th>Date Encrypted</th>
                </tr>
            </thead>
            <tbody>
                {files_rows if files_rows else "<tr><td colspan='6' style='text-align: center; color: var(--muted);'>No files encrypted yet.</td></tr>"}
            </tbody>
        </table>

        <div class="section-title"><i class="fa-solid fa-clock-rotate-left"></i> Chronological Activity & Security Audit Trail</div>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Activity Type</th>
                    <th>Status</th>
                    <th>Threat Level</th>
                    <th>Anomaly</th>
                    <th>Event Details</th>
                </tr>
            </thead>
            <tbody>
                {logs_rows if logs_rows else "<tr><td colspan='6' style='text-align: center; color: var(--muted);'>No security logs recorded.</td></tr>"}
            </tbody>
        </table>

        <div style="margin-top: 2rem; border-top: 1px solid var(--border); padding-top: 1rem; font-size: 0.75rem; color: var(--muted); text-align: center;">
            AI-Enabled Hybrid File Encryption and Threat Detection System &bull; Cryptographically Verified Audit Log
        </div>
    </div>
</body>
</html>
"""
    return html
