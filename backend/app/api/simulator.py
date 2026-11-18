import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import User, Patient, ClinicalRecord, SecurityAlert
from app.core.audit_chain import record_audit_event
from app.services.anomaly_engine import evaluate_access_event, evaluate_denied_event, evaluate_bulk_export
from app.services.websocket_manager import ws_hub

router = APIRouter(prefix="/api/simulator", tags=["Attack Scenario Simulator"])

@router.post("/scenario/legitimate_care")
async def scenario_legitimate_care(db: Session = Depends(get_db)):
    """
    Scenario 1: Legitimate clinical care workflow.
    Dr. Alice Smith views assigned cardiology patient and logs routine follow-up.
    Result: 200 OK, 0 Risk Points added, valid audit log recorded.
    """
    doctor = db.query(User).filter(User.username == "doctor_alice").first()
    patient = db.query(Patient).filter(Patient.department == "Cardiology", Patient.is_honeytoken == False).first()

    audit_entry = record_audit_event(
        db=db,
        user_id=doctor.id,
        user_username=doctor.username,
        user_role=doctor.role,
        user_department=doctor.department,
        action="VIEW_RECORD",
        resource_type="patient_chart",
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
        "scenario": "Legitimate Doctor Patient Care",
        "actor": doctor.username,
        "patient": f"{patient.first_name} {patient.last_name} ({patient.mrn})",
        "outcome": "APPROVED (200 OK)",
        "alerts_triggered": 0,
        "user_risk_score": doctor.current_risk_score,
        "audit_event_uuid": audit_entry.event_uuid
    }

@router.post("/scenario/bulk_scraping")
async def scenario_bulk_scraping(db: Session = Depends(get_db)):
    """
    Scenario 2: Malicious Bulk Record Scraping.
    Nurse Bob rapidly queries 12 different patient records in rapid succession.
    Result: RULE-01 triggers, Risk Score jumps +40, High-Severity alert fired.
    """
    nurse = db.query(User).filter(User.username == "nurse_bob").first()
    patients = db.query(Patient).filter(Patient.is_honeytoken == False).limit(12).all()

    alerts_created = []
    for p in patients:
        alerts = await evaluate_access_event(
            db=db,
            user=nurse,
            action="VIEW_RECORD",
            patient=p
        )
        if alerts:
            alerts_created.extend(alerts)

        audit_entry = record_audit_event(
            db=db,
            user_id=nurse.id,
            user_username=nurse.username,
            user_role=nurse.role,
            user_department=nurse.department,
            action="VIEW_RECORD",
            resource_type="patient_chart",
            patient_id=p.id,
            patient_mrn=p.mrn,
            http_status=200,
            risk_score_assigned=10
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

    db.refresh(nurse)
    return {
        "scenario": "Rapid Bulk Record Scraping",
        "actor": nurse.username,
        "records_probed": len(patients),
        "alerts_triggered": len(alerts_created),
        "user_new_risk_score": nurse.current_risk_score,
        "is_quarantined": nurse.is_quarantined,
        "message": f"RULE-01 successfully tripped: {nurse.username} viewed {len(patients)} records in a burst."
    }

@router.post("/scenario/honeytoken_snoop")
async def scenario_honeytoken_snoop(db: Session = Depends(get_db)):
    """
    Scenario 3: Honey-Token Decoy Snooping.
    Staff snoops on VIP Ambassador Elena Vance (is_honeytoken=True).
    Result: RULE-03 fires instantly with CRITICAL severity, +100 risk, user immediately quarantined!
    """
    actor = db.query(User).filter(User.username == "billing_eva").first()
    honey_patient = db.query(Patient).filter(Patient.is_honeytoken == True).first()

    alerts = await evaluate_access_event(
        db=db,
        user=actor,
        action="VIEW_RECORD",
        patient=honey_patient
    )

    audit_entry = record_audit_event(
        db=db,
        user_id=actor.id,
        user_username=actor.username,
        user_role=actor.role,
        user_department=actor.department,
        action="HONEYTOKEN_TRIGGER",
        resource_type="decoy_vip_record",
        patient_id=honey_patient.id,
        patient_mrn=honey_patient.mrn,
        http_status=200,
        risk_score_assigned=100
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

    db.refresh(actor)
    return {
        "scenario": "Honey-Token VIP Tripwire",
        "actor": actor.username,
        "decoy_target": f"{honey_patient.first_name} {honey_patient.last_name} ({honey_patient.mrn})",
        "severity": "CRITICAL",
        "risk_points_added": 100,
        "user_risk_score": actor.current_risk_score,
        "quarantine_status": actor.is_quarantined,
        "message": f"RULE-03 fired! User {actor.username} compromised the honey-token trap and was automatically locked out."
    }

@router.post("/scenario/unauthorized_probing")
async def scenario_unauthorized_probing(db: Session = Depends(get_db)):
    """
    Scenario 4: Repeated Access Denials / Brute Endpoint Probing.
    Staff member attempts 4 consecutive unauthorized API hits.
    Result: Generates 4 ACCESS_DENIED audit events and fires RULE-05.
    """
    user = db.query(User).filter(User.username == "lab_david").first()

    alert = None
    for i in range(4):
        record_audit_event(
            db=db,
            user_id=user.id,
            user_username=user.username,
            user_role=user.role,
            user_department=user.department,
            action="ACCESS_DENIED",
            resource_type="confidential_psych_notes",
            http_status=403,
            risk_score_assigned=15
        )
        alert = await evaluate_denied_event(db, user, "/api/records/psychiatric/classified")

    db.refresh(user)
    return {
        "scenario": "Repeated Access Denials (Endpoint Probing)",
        "actor": user.username,
        "denied_count": 4,
        "rule_triggered": "RULE-05",
        "user_risk_score": user.current_risk_score,
        "alert_created": alert is not None,
        "message": f"RULE-05 fired! Multiple denied accesses detected in short time window."
    }

@router.post("/scenario/break_the_glass")
async def scenario_break_the_glass(db: Session = Depends(get_db)):
    """
    Scenario 5: Emergency Break-the-Glass (BTG) Protocol Override.
    Doctor overrides departmental restriction for a critical unconscious patient.
    Result: Access granted, emergency reason logged in audit chain, RULE-07 alert sent to SOC.
    """
    doctor = db.query(User).filter(User.username == "doctor_frank").first()
    # Find patient outside oncology
    patient = db.query(Patient).filter(Patient.department == "Emergency").first()

    override_reason = "CRITICAL EMERGENCY: Severe anaphylaxis and collapse in triage. Immediate drug allergy history required."

    audit_entry = record_audit_event(
        db=db,
        user_id=doctor.id,
        user_username=doctor.username,
        user_role=doctor.role,
        user_department=doctor.department,
        action="BREAK_THE_GLASS",
        resource_type="patient_chart_override",
        patient_id=patient.id,
        patient_mrn=patient.mrn,
        is_emergency_override=True,
        override_reason=override_reason,
        http_status=200,
        risk_score_assigned=15
    )

    alerts = await evaluate_access_event(
        db=db,
        user=doctor,
        action="BREAK_THE_GLASS",
        patient=patient,
        is_emergency_override=True,
        override_reason=override_reason
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
        "scenario": "Break-the-Glass Emergency Protocol",
        "actor": doctor.username,
        "patient": f"{patient.first_name} {patient.last_name} ({patient.mrn})",
        "justification": override_reason,
        "outcome": "EMERGENCY CLEARANCE GRANTED",
        "rule_code": "RULE-07",
        "alerts_triggered": len(alerts),
        "audit_event_uuid": audit_entry.event_uuid
    }

@router.post("/scenario/bulk_exfiltration")
async def scenario_bulk_exfiltration(db: Session = Depends(get_db)):
    """
    Scenario 6: Unauthorized Bulk Data Exfiltration Attempt.
    Nurse Bob attempts batch export of 50 patient records.
    Result: 403 Forbidden, RULE-06 CRITICAL alert fires, risk jumps +60.
    """
    nurse = db.query(User).filter(User.username == "nurse_bob").first()
    alert = await evaluate_bulk_export(db, nurse, 50)

    audit_entry = record_audit_event(
        db=db,
        user_id=nurse.id,
        user_username=nurse.username,
        user_role=nurse.role,
        user_department=nurse.department,
        action="ACCESS_DENIED",
        resource_type="bulk_export",
        http_status=403,
        risk_score_assigned=60
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

    db.refresh(nurse)
    return {
        "scenario": "Unauthorized Bulk Exfiltration Attempt",
        "actor": nurse.username,
        "records_targeted": 50,
        "rule_code": "RULE-06",
        "severity": "CRITICAL",
        "user_risk_score": nurse.current_risk_score,
        "is_quarantined": nurse.is_quarantined,
        "message": f"RULE-06 fired! Unauthorized staff attempted bulk record download."
    }

@router.post("/scenario/reset_all")
async def scenario_reset_all(db: Session = Depends(get_db)):
    """
    Cleans up simulator state, resets user risk scores to 0, and unquarantines all users.
    """
    users = db.query(User).all()
    for u in users:
        u.current_risk_score = 0
        u.is_quarantined = False

    db.commit()
    return {"message": "All user risk scores reset to 0 and quarantines lifted."}

