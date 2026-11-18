from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import User, Patient, ClinicalRecord
from app.services.rbac_abac import get_current_user, verify_rbac_abac_permission
from app.core.audit_chain import record_audit_event
from app.services.anomaly_engine import evaluate_bulk_export
from app.services.websocket_manager import ws_hub

router = APIRouter(prefix="/api/records", tags=["Clinical Records"])

class ClinicalRecordCreate(BaseModel):
    patient_id: int
    record_type: str  # vitals, clinical_notes, prescription, lab_result, billing
    title: str
    content: str
    sensitivity_level: Optional[str] = "standard"

@router.post("")
async def create_record(
    req: ClinicalRecordCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    patient = db.query(Patient).filter(Patient.id == req.patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found.")

    # Map record_type to resource
    resource_map = {
        "vitals": "vitals",
        "prescription": "prescriptions",
        "clinical_notes": "clinical_notes",
        "lab_result": "lab_results",
        "billing": "billing"
    }
    resource = resource_map.get(req.record_type, "clinical_notes")

    await verify_rbac_abac_permission(
        user=current_user,
        resource=resource,
        action="write",
        db=db,
        patient=patient,
        request_endpoint="/api/records"
    )

    new_record = ClinicalRecord(
        patient_id=req.patient_id,
        author_id=current_user.id,
        record_type=req.record_type,
        title=req.title,
        content=req.content,
        sensitivity_level=req.sensitivity_level or "standard"
    )
    db.add(new_record)
    db.commit()
    db.refresh(new_record)

    client_ip = request.client.host if request.client else "127.0.0.1"
    audit_entry = record_audit_event(
        db=db,
        user_id=current_user.id,
        user_username=current_user.username,
        user_role=current_user.role,
        user_department=current_user.department,
        client_ip=client_ip,
        action="CREATE_RECORD",
        resource_type=req.record_type,
        resource_id=new_record.id,
        patient_id=patient.id,
        patient_mrn=patient.mrn,
        http_status=200,
        risk_score_assigned=0
    )

    await ws_hub.broadcast_audit({
        "id": audit_entry.id,
        "timestamp": audit_entry.timestamp.isoformat(),
        "user_username": audit_entry.user_username,
        "user_role": audit_entry.user_role,
        "action": audit_entry.action,
        "patient_mrn": audit_entry.patient_mrn,
        "resource_type": audit_entry.resource_type,
        "record_hash": audit_entry.record_hash[:16] + "..."
    })

    return {
        "id": new_record.id,
        "patient_id": new_record.patient_id,
        "record_type": new_record.record_type,
        "title": new_record.title,
        "content": new_record.content,
        "created_at": new_record.created_at.isoformat() if new_record.created_at else None
    }

@router.get("/export")
async def export_records(
    request: Request,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Simulates bulk data export.
    Evaluates:
    RULE-06: Unauthorized Bulk Exfiltration Attempt if triggered by unauthorized roles.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Evaluate potential data exfiltration
    if current_user.role not in ["AUDITOR", "ADMIN"]:
        await evaluate_bulk_export(db, current_user, limit)

        record_audit_event(
            db=db,
            user_id=current_user.id,
            user_username=current_user.username,
            user_role=current_user.role,
            user_department=current_user.department,
            client_ip=client_ip,
            action="ACCESS_DENIED",
            resource_type="bulk_export",
            http_status=403,
            risk_score_assigned=60
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CRITICAL SECURITY POLICY: Bulk PHI export is prohibited for standard clinical staff without Compliance Auditor clearance."
        )

    # If Auditor or Admin, grant sanitized export
    records = db.query(ClinicalRecord).limit(limit).all()
    audit_entry = record_audit_event(
        db=db,
        user_id=current_user.id,
        user_username=current_user.username,
        user_role=current_user.role,
        user_department=current_user.department,
        client_ip=client_ip,
        action="EXPORT_RECORDS",
        resource_type="bulk_export",
        http_status=200,
        risk_score_assigned=0
    )

    await ws_hub.broadcast_audit({
        "id": audit_entry.id,
        "timestamp": audit_entry.timestamp.isoformat(),
        "user_username": audit_entry.user_username,
        "user_role": audit_entry.user_role,
        "action": audit_entry.action,
        "resource_type": audit_entry.resource_type,
        "record_hash": audit_entry.record_hash[:16] + "..."
    })

    return {
        "status": "SUCCESS",
        "exported_by": current_user.username,
        "record_count": len(records),
        "audit_event_uuid": audit_entry.event_uuid,
        "records": [
            {
                "id": r.id,
                "patient_id": r.patient_id,
                "record_type": r.record_type,
                "title": r.title,
                "sensitivity_level": r.sensitivity_level
            }
            for r in records
        ]
    }

