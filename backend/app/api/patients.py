import uuid
import json
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import User, Patient, ClinicalRecord, PatientAssignment
from app.services.rbac_abac import get_current_user, verify_rbac_abac_permission
from app.core.audit_chain import record_audit_event
from app.services.anomaly_engine import evaluate_access_event
from app.services.websocket_manager import ws_hub

router = APIRouter(prefix="/api/patients", tags=["Patients"])

class BreakTheGlassRequest(BaseModel):
    reason: str

class PatientCreate(BaseModel):
    first_name: str
    last_name: str
    dob: str
    gender: str
    department: str
    ward_room: str

@router.get("")
async def list_patients(
    request: Request,
    department: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lists patients with department/assignment filtering and demographic permissions.
    """
    await verify_rbac_abac_permission(
        user=current_user,
        resource="demographics",
        action="read",
        db=db,
        request_endpoint="/api/patients"
    )

    query = db.query(Patient)
    if department:
        query = query.filter(Patient.department == department)
    if search:
        search_filter = f"%{search}%"
        query = query.filter(
            (Patient.first_name.ilike(search_filter)) |
            (Patient.last_name.ilike(search_filter)) |
            (Patient.mrn.ilike(search_filter))
        )

    patients = query.order_by(Patient.id.asc()).all()

    # Record audit log for directory view
    client_ip = request.client.host if request.client else "127.0.0.1"
    audit_entry = record_audit_event(
        db=db,
        user_id=current_user.id,
        user_username=current_user.username,
        user_role=current_user.role,
        user_department=current_user.department,
        client_ip=client_ip,
        action="VIEW_DIRECTORY",
        resource_type="patient_directory",
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

    return [
        {
            "id": p.id,
            "mrn": p.mrn,
            "first_name": p.first_name,
            "last_name": p.last_name,
            "dob": p.dob.isoformat() if p.dob else None,
            "gender": p.gender,
            "department": p.department,
            "ward_room": p.ward_room,
            "is_vip": p.is_vip,
            "is_honeytoken": p.is_honeytoken,
            "appointments": json.loads(p.appointments) if p.appointments else []
        }
        for p in patients
    ]

@router.get("/{patient_id}")
async def get_patient_detail(
    patient_id: int,
    request: Request,
    is_emergency_override: bool = Query(False),
    override_reason: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Fetches full clinical details for a single patient record.
    Evaluates:
    1. Tripwire Honey-Token (RULE-03)
    2. Bulk Scraping Sliding Window (RULE-01)
    3. Department / Scope Mismatch (RULE-02)
    4. Off-Hours Shift Anomaly (RULE-04)
    5. Break-the-Glass Emergency Protocol (RULE-07)
    """
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient record not found.")

    client_ip = request.client.host if request.client else "127.0.0.1"

    # Evaluate all behavioral threat rules
    await evaluate_access_event(
        db=db,
        user=current_user,
        action="VIEW_RECORD",
        patient=patient,
        is_emergency_override=is_emergency_override,
        override_reason=override_reason
    )

    # Coarse check
    await verify_rbac_abac_permission(
        user=current_user,
        resource="demographics",
        action="read",
        db=db,
        patient=patient,
        is_emergency_override=is_emergency_override,
        override_reason=override_reason,
        request_endpoint=f"/api/patients/{patient_id}"
    )

    # Record in immutable SHA-256 audit chain
    audit_action = "BREAK_THE_GLASS" if is_emergency_override else "VIEW_RECORD"
    audit_entry = record_audit_event(
        db=db,
        user_id=current_user.id,
        user_username=current_user.username,
        user_role=current_user.role,
        user_department=current_user.department,
        client_ip=client_ip,
        action=audit_action,
        resource_type="patient_chart",
        patient_id=patient.id,
        patient_mrn=patient.mrn,
        is_emergency_override=is_emergency_override,
        override_reason=override_reason,
        http_status=200,
        risk_score_assigned=0 if not is_emergency_override else 15
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

    # Filter clinical records based on user role (RBAC/ABAC data filtering)
    records = db.query(ClinicalRecord).filter(ClinicalRecord.patient_id == patient.id).all()
    filtered_records = []

    for r in records:
        can_view = False
        if current_user.role in ["DOCTOR", "ADMIN"] or is_emergency_override:
            can_view = True
        elif current_user.role == "NURSE":
            # Nurses view vitals, prescriptions, standard notes, lab results
            if r.record_type in ["vitals", "prescription", "lab_result"]:
                can_view = True
            elif r.record_type == "clinical_notes" and r.sensitivity_level != "confidential":
                can_view = True
        elif current_user.role == "LAB_TECH":
            if r.record_type == "lab_result":
                can_view = True
        elif current_user.role == "BILLING":
            if r.record_type == "billing":
                can_view = True

        if can_view:
            filtered_records.append({
                "id": r.id,
                "record_type": r.record_type,
                "title": r.title,
                "content": r.content,
                "sensitivity_level": r.sensitivity_level,
                "author_id": r.author_id,
                "created_at": r.created_at.isoformat() if r.created_at else None
            })

    return {
        "id": patient.id,
        "mrn": patient.mrn,
        "first_name": patient.first_name,
        "last_name": patient.last_name,
        "dob": patient.dob.isoformat() if patient.dob else None,
        "gender": patient.gender,
        "department": patient.department,
        "ward_room": patient.ward_room,
        "is_vip": patient.is_vip,
        "is_honeytoken": patient.is_honeytoken,
        "records": filtered_records,
        "appointments": json.loads(patient.appointments) if patient.appointments else [],
        "is_emergency_override_active": is_emergency_override,
        "compliance_metadata": {
            "hipaa_minimum_necessary": True,
            "citation": "45 CFR §164.502(b) & NIST AC-6 Least Privilege",
            "audit_hash": audit_entry.record_hash
        }
    }

@router.post("/{patient_id}/break-the-glass")
async def break_the_glass_override(
    patient_id: int,
    req: BreakTheGlassRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Executes emergency Break-The-Glass protocol. Grants immediate clinical access
    with mandatory justification and triggers automated SOC security alerts.
    """
    if current_user.role not in ["DOCTOR", "NURSE"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Break-The-Glass emergency override is restricted to licensed Clinical Staff (Doctors and Nurses)."
        )

    if not req.reason or len(req.reason.strip()) < 5:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mandatory justification required for Break-the-Glass clinical override (minimum 5 characters)."
        )

    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient record not found.")

    # Record emergency event
    client_ip = request.client.host if request.client else "127.0.0.1"
    audit_entry = record_audit_event(
        db=db,
        user_id=current_user.id,
        user_username=current_user.username,
        user_role=current_user.role,
        user_department=current_user.department,
        client_ip=client_ip,
        action="BREAK_THE_GLASS",
        resource_type="patient_chart_override",
        patient_id=patient.id,
        patient_mrn=patient.mrn,
        is_emergency_override=True,
        override_reason=req.reason,
        http_status=200,
        risk_score_assigned=15
    )

    # Evaluate threat engine (triggers RULE-07)
    await evaluate_access_event(
        db=db,
        user=current_user,
        action="BREAK_THE_GLASS",
        patient=patient,
        is_emergency_override=True,
        override_reason=req.reason
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
        "success": True,
        "message": f"Emergency Break-The-Glass clearance granted for Patient #{patient.mrn}.",
        "reason_logged": req.reason,
        "audit_event_uuid": audit_entry.event_uuid
    }

# ================= APPOINTMENTS & RECEPTION SCHEDULING (BILLING / RECEPTION & ADMIN) =================

class AppointmentCreateRequest(BaseModel):
    date: str
    time: str
    department: str
    staff: str
    purpose: str
    status: Optional[str] = "Scheduled"

class AppointmentUpdateRequest(BaseModel):
    date: Optional[str] = None
    time: Optional[str] = None
    department: Optional[str] = None
    staff: Optional[str] = None
    purpose: Optional[str] = None
    status: Optional[str] = None

@router.post("/{patient_id}/appointments")
async def create_appointment(
    patient_id: int,
    req: AppointmentCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Schedules a new patient appointment.
    Restricted to Reception / Billing and Admin roles in accordance with HIPAA & RBAC separation of duties.
    """
    if current_user.role not in ["BILLING", "ADMIN"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: Role '{current_user.role}' is not authorized to schedule appointments. Billing and Reception clearance required."
        )

    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient record not found.")

    apts = json.loads(patient.appointments) if patient.appointments else []
    new_id = f"APT-{uuid.uuid4().hex[:6].upper()}"

    new_apt = {
        "id": new_id,
        "date": req.date,
        "time": req.time,
        "department": req.department,
        "staff": req.staff,
        "purpose": req.purpose,
        "status": req.status or "Scheduled",
        "created_by": current_user.email or current_user.username
    }

    apts.append(new_apt)
    patient.appointments = json.dumps(apts)
    db.commit()

    client_ip = request.client.host if request.client else "127.0.0.1"
    audit_entry = record_audit_event(
        db=db,
        user_id=current_user.id,
        user_username=current_user.username,
        user_role=current_user.role,
        user_department=current_user.department,
        client_ip=client_ip,
        action="APPOINTMENT_SCHEDULED",
        resource_type="appointments",
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

    return {"message": "Appointment scheduled successfully.", "appointment": new_apt}

@router.put("/{patient_id}/appointments/{appointment_id}")
async def update_appointment(
    patient_id: int,
    appointment_id: str,
    req: AppointmentUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Updates an existing patient appointment.
    Restricted to Reception / Billing and Admin roles.
    """
    if current_user.role not in ["BILLING", "ADMIN"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: Role '{current_user.role}' is not authorized to update appointments. Billing and Reception clearance required."
        )

    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient record not found.")

    apts = json.loads(patient.appointments) if patient.appointments else []
    target_apt = None
    for a in apts:
        if a.get("id") == appointment_id:
            target_apt = a
            break

    if not target_apt:
        raise HTTPException(status_code=404, detail=f"Appointment '{appointment_id}' not found.")

    if req.date is not None: target_apt["date"] = req.date
    if req.time is not None: target_apt["time"] = req.time
    if req.department is not None: target_apt["department"] = req.department
    if req.staff is not None: target_apt["staff"] = req.staff
    if req.purpose is not None: target_apt["purpose"] = req.purpose
    if req.status is not None: target_apt["status"] = req.status
    target_apt["updated_by"] = current_user.email or current_user.username

    patient.appointments = json.dumps(apts)
    db.commit()

    client_ip = request.client.host if request.client else "127.0.0.1"
    audit_entry = record_audit_event(
        db=db,
        user_id=current_user.id,
        user_username=current_user.username,
        user_role=current_user.role,
        user_department=current_user.department,
        client_ip=client_ip,
        action="APPOINTMENT_UPDATED",
        resource_type="appointments",
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

    return {"message": "Appointment updated successfully.", "appointment": target_apt}

@router.delete("/{patient_id}/appointments/{appointment_id}")
async def delete_appointment(
    patient_id: int,
    appointment_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Cancels or removes a patient appointment.
    Restricted to Reception / Billing and Admin roles.
    """
    if current_user.role not in ["BILLING", "ADMIN"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: Role '{current_user.role}' is not authorized to remove appointments. Billing and Reception clearance required."
        )

    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient record not found.")

    apts = json.loads(patient.appointments) if patient.appointments else []
    initial_len = len(apts)
    apts = [a for a in apts if a.get("id") != appointment_id]

    if len(apts) == initial_len:
        raise HTTPException(status_code=404, detail=f"Appointment '{appointment_id}' not found.")

    patient.appointments = json.dumps(apts)
    db.commit()

    client_ip = request.client.host if request.client else "127.0.0.1"
    audit_entry = record_audit_event(
        db=db,
        user_id=current_user.id,
        user_username=current_user.username,
        user_role=current_user.role,
        user_department=current_user.department,
        client_ip=client_ip,
        action="APPOINTMENT_REMOVED",
        resource_type="appointments",
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

    return {"message": f"Appointment '{appointment_id}' removed successfully.", "remaining_appointments": len(apts)}

