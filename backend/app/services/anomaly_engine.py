import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Set, Any, Tuple
from sqlalchemy.orm import Session
from app.db.models import User, Patient, SecurityAlert, AuditLog
from app.core.config import RULE_CONFIG
from app.services.websocket_manager import ws_hub

class SlidingWindowMemory:
    """
    In-memory tracking for high-velocity and sliding window detection rules.
    """
    def __init__(self):
        # user_id -> List[Tuple[timestamp, patient_id]]
        self.patient_views: Dict[int, List[Tuple[datetime, int]]] = {}
        # user_id -> List[timestamp]
        self.denied_attempts: Dict[int, List[datetime]] = {}

    def record_view(self, user_id: int, patient_id: int):
        now = datetime.now(timezone.utc)
        if user_id not in self.patient_views:
            self.patient_views[user_id] = []
        self.patient_views[user_id].append((now, patient_id))
        self._prune(user_id)

    def record_denied(self, user_id: int):
        now = datetime.now(timezone.utc)
        if user_id not in self.denied_attempts:
            self.denied_attempts[user_id] = []
        self.denied_attempts[user_id].append(now)
        self._prune_denied(user_id)

    def get_recent_unique_patients_count(self, user_id: int, window_sec: int) -> int:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=window_sec)
        entries = self.patient_views.get(user_id, [])
        recent_pat_ids = {pid for ts, pid in entries if ts >= cutoff}
        return len(recent_pat_ids)

    def get_recent_denied_count(self, user_id: int, window_sec: int) -> int:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=window_sec)
        entries = self.denied_attempts.get(user_id, [])
        return sum(1 for ts in entries if ts >= cutoff)

    def _prune(self, user_id: int):
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=10)
        self.patient_views[user_id] = [
            (ts, pid) for ts, pid in self.patient_views[user_id] if ts >= cutoff
        ]

    def _prune_denied(self, user_id: int):
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=10)
        self.denied_attempts[user_id] = [
            ts for ts in self.denied_attempts[user_id] if ts >= cutoff
        ]

window_memory = SlidingWindowMemory()

async def trigger_security_alert(
    db: Session,
    rule_code: str,
    rule_name: str,
    severity: str,
    user: Optional[User],
    patient: Optional[Patient],
    risk_delta: int,
    description: str,
    context: Dict[str, Any]
) -> SecurityAlert:
    """
    Persists a security alert, updates user risk profile, and broadcasts via WebSockets.
    """
    alert_uuid = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    alert = SecurityAlert(
        alert_uuid=alert_uuid,
        timestamp=now,
        rule_code=rule_code,
        rule_name=rule_name,
        severity=severity,
        user_id=user.id if user else None,
        user_username=user.username if user else "anonymous",
        patient_id=patient.id if patient else None,
        patient_mrn=patient.mrn if patient else None,
        risk_score_delta=risk_delta,
        description=description,
        context_json=json.dumps(context),
        status="ACTIVE"
    )
    db.add(alert)

    # Accumulate dynamic risk score on user
    if user:
        user.current_risk_score = min(100, user.current_risk_score + risk_delta)
        if user.current_risk_score >= 85 or severity == "CRITICAL":
            user.is_quarantined = True

    db.commit()
    db.refresh(alert)

    # Broadcast alert payload to SOC dashboard
    alert_payload = {
        "id": alert.id,
        "alert_uuid": alert.alert_uuid,
        "timestamp": alert.timestamp.isoformat(),
        "rule_code": alert.rule_code,
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "user_id": alert.user_id,
        "user_username": alert.user_username,
        "patient_id": alert.patient_id,
        "patient_mrn": alert.patient_mrn,
        "risk_score_delta": alert.risk_score_delta,
        "user_current_risk": user.current_risk_score if user else 0,
        "description": alert.description,
        "context": context,
        "status": alert.status
    }
    await ws_hub.broadcast_alert(alert_payload)
    return alert

def check_shift_anomaly(user: User, request_time: Optional[datetime] = None) -> Tuple[bool, str]:
    """
    Evaluates whether the access falls outside assigned shift hours (> 2 hours offset).
    """
    if not user.shift_start or not user.shift_end:
        return False, "No shift defined"

    req_time = request_time or datetime.now(timezone.utc)
    current_minutes = req_time.hour * 60 + req_time.minute

    try:
        sh_start_h, sh_start_m = map(int, user.shift_start.split(":"))
        sh_end_h, sh_end_m = map(int, user.shift_end.split(":"))
        start_min = sh_start_h * 60 + sh_start_m
        end_min = sh_end_h * 60 + sh_end_m
    except Exception:
        return False, "Invalid shift format"

    # Handle standard vs overnight shift
    is_inside = False
    if start_min <= end_min:
        is_inside = (start_min <= current_minutes <= end_min)
    else:  # Overnight shift (e.g. 20:00 to 06:00)
        is_inside = (current_minutes >= start_min or current_minutes <= end_min)

    if is_inside:
        return False, "Within shift"

    # Calculate distance from shift window
    dist = 0
    if start_min <= end_min:
        dist = min(abs(current_minutes - start_min), abs(current_minutes - end_min))
    else:
        # Distance to wrap around
        dist = min(abs(current_minutes - start_min), abs(current_minutes - end_min))

    # If > 120 minutes outside shift
    if dist >= 120:
        return True, f"Access outside shift window ({user.shift_start}-{user.shift_end}) by {dist} mins."
    return False, "Within grace tolerance"

async def evaluate_access_event(
    db: Session,
    user: User,
    action: str,
    patient: Optional[Patient] = None,
    is_emergency_override: bool = False,
    override_reason: Optional[str] = None
) -> List[SecurityAlert]:
    """
    Master Behavioral Anomaly Engine. Evaluates incoming action against all 7 security rules.
    """
    generated_alerts = []

    # RULE-03: Honey-Token / VIP Tripwire (Highest priority)
    if patient and patient.is_honeytoken:
        alert = await trigger_security_alert(
            db=db,
            rule_code="RULE-03",
            rule_name="Honey-Token Tripwire Triggered",
            severity="CRITICAL",
            user=user,
            patient=patient,
            risk_delta=100,
            description=f"CRITICAL: User '{user.username}' accessed decoy honey-token patient record #{patient.mrn} ({patient.first_name} {patient.last_name}). Immediate security tripwire tripped!",
            context={
                "tripwire_type": "HONEY_TOKEN_RECORD",
                "patient_mrn": patient.mrn,
                "action": action,
                "quarantine_applied": True
            }
        )
        generated_alerts.append(alert)

    # Record view in sliding memory for velocity checks
    if patient and action in ["VIEW_RECORD", "VIEW_PATIENT"]:
        window_memory.record_view(user.id, patient.id)
        recent_count = window_memory.get_recent_unique_patients_count(
            user.id, RULE_CONFIG["BULK_VIEW_WINDOW_SEC"]
        )

        # RULE-01: Bulk Scraping
        if recent_count >= RULE_CONFIG["BULK_VIEW_THRESHOLD"]:
            alert = await trigger_security_alert(
                db=db,
                rule_code="RULE-01",
                rule_name="Rapid Bulk Record Scraping",
                severity="HIGH",
                user=user,
                patient=patient,
                risk_delta=40,
                description=f"User '{user.username}' viewed {recent_count} unique patient records within {RULE_CONFIG['BULK_VIEW_WINDOW_SEC']}s window. Exceeds scrap threshold ({RULE_CONFIG['BULK_VIEW_THRESHOLD']}).",
                context={
                    "unique_patients_viewed": recent_count,
                    "window_seconds": RULE_CONFIG["BULK_VIEW_WINDOW_SEC"]
                }
            )
            generated_alerts.append(alert)

        # RULE-02: Scope / Department Mismatch (Doctor/Nurse accessing patient outside department without BTG)
        if patient.department != user.department and user.role in ["DOCTOR", "NURSE"] and not is_emergency_override:
            # Check assignment
            from app.db.models import PatientAssignment
            assignment = db.query(PatientAssignment).filter(
                PatientAssignment.staff_id == user.id,
                PatientAssignment.patient_id == patient.id,
                PatientAssignment.is_active == True
            ).first()

            if not assignment:
                alert = await trigger_security_alert(
                    db=db,
                    rule_code="RULE-02",
                    rule_name="Out-of-Scope Department Access",
                    severity="MEDIUM",
                    user=user,
                    patient=patient,
                    risk_delta=25,
                    description=f"Staff '{user.username}' ({user.department}) accessed patient #{patient.mrn} from ({patient.department}) without active clinical assignment.",
                    context={
                        "user_department": user.department,
                        "patient_department": patient.department,
                        "care_assignment": False
                    }
                )
                generated_alerts.append(alert)

    # RULE-04: Off-Hours / Shift Anomaly
    if user.role in ["NURSE", "LAB_TECH", "BILLING"]:
        is_anomaly, reason = check_shift_anomaly(user)
        if is_anomaly:
            alert = await trigger_security_alert(
                db=db,
                rule_code="RULE-04",
                rule_name="Off-Hours Shift Anomaly",
                severity="MEDIUM",
                user=user,
                patient=patient,
                risk_delta=20,
                description=f"Staff '{user.username}' accessed records outside designated shift: {reason}",
                context={
                    "shift_start": user.shift_start,
                    "shift_end": user.shift_end,
                    "reason": reason
                }
            )
            generated_alerts.append(alert)

    # RULE-07: Break-the-Glass Emergency Protocol Invocation
    if is_emergency_override:
        alert = await trigger_security_alert(
            db=db,
            rule_code="RULE-07",
            rule_name="Break-the-Glass Emergency Access",
            severity="LOW",
            user=user,
            patient=patient,
            risk_delta=15,
            description=f"Emergency override invoked by '{user.username}' for patient #{patient.mrn if patient else 'N/A'}. Reason: {override_reason or 'No justification provided'}",
            context={
                "override_reason": override_reason,
                "protocol": "BREAK_THE_GLASS",
                "requires_soc_audit": True
            }
        )
        generated_alerts.append(alert)

    return generated_alerts

async def evaluate_denied_event(db: Session, user: User, requested_endpoint: str) -> Optional[SecurityAlert]:
    """
    Evaluates repeated unauthorized access blocks (RULE-05).
    """
    window_memory.record_denied(user.id)
    denied_count = window_memory.get_recent_denied_count(user.id, RULE_CONFIG["DENIED_WINDOW_SEC"])

    if denied_count >= RULE_CONFIG["DENIED_THRESHOLD"]:
        return await trigger_security_alert(
            db=db,
            rule_code="RULE-05",
            rule_name="Repeated Access Denials (Endpoint Probing)",
            severity="HIGH",
            user=user,
            patient=None,
            risk_delta=35,
            description=f"User '{user.username}' triggered {denied_count} ACCESS_DENIED events within {RULE_CONFIG['DENIED_WINDOW_SEC']}s. Possible unauthorized probing.",
            context={
                "denied_count": denied_count,
                "window_seconds": RULE_CONFIG["DENIED_WINDOW_SEC"],
                "last_endpoint": requested_endpoint
            }
        )
    return None

async def evaluate_bulk_export(db: Session, user: User, record_count: int) -> Optional[SecurityAlert]:
    """
    Evaluates bulk export or unauthorized data exfiltration (RULE-06).
    """
    if user.role != "AUDITOR" and user.role != "ADMIN":
        return await trigger_security_alert(
            db=db,
            rule_code="RULE-06",
            rule_name="Unauthorized Bulk Exfiltration Attempt",
            severity="CRITICAL",
            user=user,
            patient=None,
            risk_delta=60,
            description=f"Unauthorized staff '{user.username}' ({user.role}) initiated batch data export of {record_count} patient records.",
            context={
                "user_role": user.role,
                "records_requested": record_count,
                "policy": "ONLY_AUDITOR_EXPORT_PERMITTED"
            }
        )
    return None

