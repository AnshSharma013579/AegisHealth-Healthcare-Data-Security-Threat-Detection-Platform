import csv
import io
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import AuditLog, User
from app.services.rbac_abac import get_current_user, require_soc_access
from app.core.audit_chain import verify_blockchain_integrity, simulate_audit_tampering

router = APIRouter(prefix="/api/audit", tags=["Audit & Cryptographic Ledger"])

@router.get("/logs")
async def get_audit_logs(
    user_filter: Optional[str] = None,
    action_filter: Optional[str] = None,
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_soc_access)
):
    """
    Returns immutable audit logs for the SOC Explorer.
    Accessible only to AUDITOR and ADMIN.
    """
    query = db.query(AuditLog).order_by(AuditLog.id.desc())
    if user_filter:
        query = query.filter(AuditLog.user_username.ilike(f"%{user_filter}%"))
    if action_filter:
        query = query.filter(AuditLog.action == action_filter)

    logs = query.limit(limit).all()

    return [
        {
            "id": l.id,
            "event_uuid": l.event_uuid,
            "timestamp": l.timestamp.isoformat() if l.timestamp else None,
            "user_username": l.user_username,
            "user_role": l.user_role,
            "user_department": l.user_department,
            "client_ip": l.client_ip,
            "action": l.action,
            "resource_type": l.resource_type,
            "patient_mrn": l.patient_mrn,
            "is_emergency_override": l.is_emergency_override,
            "override_reason": l.override_reason,
            "http_status": l.http_status,
            "risk_score_assigned": l.risk_score_assigned,
            "prev_hash": l.prev_hash,
            "record_hash": l.record_hash
        }
        for l in logs
    ]

@router.get("/verify-integrity")
async def verify_chain(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_soc_access)
):
    """
    Scans entire audit chain from Genesis to latest block.
    Verifies SHA-256 hash chaining and data immutability.
    """
    result = verify_blockchain_integrity(db)
    return result

@router.post("/simulate-tampering")
async def tamper_log_entry(
    target_id: Optional[int] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_soc_access)
):
    """
    Hackathon Demo Tool: Modifies an audit log entry in place without updating cryptographic hashes,
    allowing judges to observe real-time cryptographic tamper detection.
    """
    result = simulate_audit_tampering(db, target_id=target_id)
    return result

@router.get("/export-csv")
async def export_audit_csv(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_soc_access)
):
    """
    Exports cryptographic audit ledger as HIPAA/GDPR-compliant CSV report.
    """
    logs = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Block ID", "Event UUID", "Timestamp (UTC)", "User", "Role", "Department",
        "Client IP", "Action", "Resource Type", "Patient MRN", "Emergency Override",
        "Override Reason", "HTTP Status", "Prev Hash", "Record Hash (SHA-256)"
    ])

    for l in logs:
        writer.writerow([
            l.id,
            l.event_uuid,
            l.timestamp.isoformat() if l.timestamp else "",
            l.user_username,
            l.user_role,
            l.user_department,
            l.client_ip,
            l.action,
            l.resource_type,
            l.patient_mrn or "",
            "YES" if l.is_emergency_override else "NO",
            l.override_reason or "",
            l.http_status,
            l.prev_hash,
            l.record_hash
        ])

    csv_data = output.getvalue()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=aegis_audit_ledger.csv"}
    )

