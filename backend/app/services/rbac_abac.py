from typing import Optional, List, Dict
from fastapi import Depends, HTTPException, status, Header, Request
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import User, Patient, ClinicalRecord, PatientAssignment
from app.core.security import decode_access_token
from app.core.audit_chain import record_audit_event
from app.services.anomaly_engine import evaluate_denied_event

# Coarse-grained Role-Based Access Control matrix
ROLE_PERMISSIONS: Dict[str, Dict[str, List[str]]] = {
    "DOCTOR": {
        "demographics": ["read"],
        "appointments": ["read"],
        "vitals": ["read", "write"],
        "prescriptions": ["read", "write"],
        "clinical_notes": ["read", "write"],
        "lab_results": ["read", "write"],
        "billing": ["read"],
        "export": ["read"],
        "break_the_glass": ["execute"]
    },
    "NURSE": {
        "demographics": ["read"],
        "appointments": ["read"],
        "vitals": ["read", "write"],
        "prescriptions": ["read"],
        "clinical_notes": ["read"],  # Read only summary/standard
        "lab_results": ["read"],
        "billing": [],
        "export": [],
        "break_the_glass": ["execute"]
    },
    "LAB_TECH": {
        "demographics": ["read"],
        "appointments": ["read"],
        "vitals": [],
        "prescriptions": [],
        "clinical_notes": [],
        "lab_results": ["read", "write"],
        "billing": [],
        "export": [],
        "break_the_glass": []
    },
    "BILLING": {
        "demographics": ["read", "write"],
        "appointments": ["read", "write"],
        "vitals": [],
        "prescriptions": [],
        "clinical_notes": [],
        "lab_results": [],
        "billing": ["read", "write"],
        "export": [],
        "break_the_glass": []
    },
    "ADMIN": {
        "demographics": ["read", "write"],
        "appointments": ["read", "write"],
        "vitals": ["read"],
        "prescriptions": ["read"],
        "clinical_notes": [],
        "lab_results": ["read"],
        "billing": ["read"],
        "export": ["read"],
        "break_the_glass": []
    },
    "AUDITOR": {
        "demographics": ["read"],
        "appointments": ["read"],
        "vitals": [],
        "prescriptions": [],
        "clinical_notes": [],
        "lab_results": [],
        "billing": [],
        "export": ["read"],
        "audit_logs": ["read", "write", "export"],
        "soc_dashboard": ["read", "write"],
        "break_the_glass": []
    }
}

async def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(None)
) -> User:
    """
    Extracts and authenticates user via Bearer JWT token from header or cookie.
    """
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
    elif "access_token" in request.cookies:
        token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials missing.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token expired or invalid signature.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.username == payload["sub"]).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account no longer exists."
        )

    if user.is_quarantined:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CRITICAL SECURITY ALERT: Account quarantined due to behavioral anomaly violations. Contact SOC."
        )

    return user

async def require_soc_access(current_user: User = Depends(get_current_user)) -> User:
    """
    Restricts access to Security Operations Center (SOC) and Audit Ledger infrastructure.
    Only users with 'AUDITOR' or 'ADMIN' role are granted clearance.
    Clinical staff (DOCTOR, NURSE, LAB_TECH, BILLING) are strictly denied.
    """
    if current_user.role not in ["AUDITOR", "ADMIN"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: Role '{current_user.role}' is not authorized to access Cyber SOC or Cryptographic Audit infrastructure. Auditor or Admin clearance required."
        )
    return current_user

async def verify_rbac_abac_permission(
    user: User,
    resource: str,
    action: str,  # "read" or "write"
    db: Session,
    patient: Optional[Patient] = None,
    record: Optional[ClinicalRecord] = None,
    is_emergency_override: bool = False,
    override_reason: Optional[str] = None,
    request_endpoint: str = ""
) -> bool:
    """
    Unified Two-Tier Authorization Engine:
    Tier 1: Role-Based Access Control (RBAC)
    Tier 2: Attribute-Based Access Control (ABAC) with Dynamic Context & Break-the-Glass
    """
    role_perms = ROLE_PERMISSIONS.get(user.role, {})
    allowed_actions = role_perms.get(resource, [])

    # Tier 1: Check RBAC
    if action not in allowed_actions:
        # Check if Break-the-Glass applies for Doctors/Nurses in emergency
        if is_emergency_override and override_reason and len(override_reason.strip()) >= 5:
            if "break_the_glass" in role_perms and "execute" in role_perms["break_the_glass"]:
                # Break-The-Glass is permitted for clinical emergency
                return True

        # RBAC Violation: Record Audit Log and check for Repeated Denials
        record_audit_event(
            db=db,
            user_id=user.id,
            user_username=user.username,
            user_role=user.role,
            user_department=user.department,
            action="ACCESS_DENIED",
            resource_type=resource,
            patient_id=patient.id if patient else (record.patient_id if record else None),
            patient_mrn=patient.mrn if patient else None,
            http_status=403,
            risk_score_assigned=15
        )
        await evaluate_denied_event(db, user, request_endpoint)

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: Role '{user.role}' lacks '{action}' privilege on resource '{resource}'."
        )

    # Tier 2: Check ABAC Dynamic Context Constraints
    if record:
        # Check sensitivity level: 'confidential' notes require Doctor or explicit Assignment
        if record.sensitivity_level == "confidential" and user.role != "DOCTOR" and not is_emergency_override:
            record_audit_event(
                db=db,
                user_id=user.id,
                user_username=user.username,
                user_role=user.role,
                user_department=user.department,
                action="ACCESS_DENIED",
                resource_type=f"{resource}:confidential",
                patient_id=record.patient_id,
                http_status=403,
                risk_score_assigned=25
            )
            await evaluate_denied_event(db, user, request_endpoint)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access Denied: Highly confidential medical record requires Attending Doctor clearance or Break-the-Glass emergency waiver."
            )

    return True

