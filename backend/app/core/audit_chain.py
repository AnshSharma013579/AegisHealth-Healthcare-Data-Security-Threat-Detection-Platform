import hashlib
import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy.orm import Session
from app.core.config import GENESIS_HASH
from app.db.models import AuditLog

def compute_payload_hash(prev_hash: str, payload: Dict[str, Any]) -> str:
    """
    Computes deterministic SHA-256 hash for a log entry chained to prev_hash.
    """
    canonical_repr = (
        f"prev:{prev_hash}|"
        f"uuid:{payload.get('event_uuid', '')}|"
        f"ts:{payload.get('timestamp', '')}|"
        f"user:{payload.get('user_username', '')}|"
        f"role:{payload.get('user_role', '')}|"
        f"action:{payload.get('action', '')}|"
        f"res_type:{payload.get('resource_type', '')}|"
        f"res_id:{payload.get('resource_id', '')}|"
        f"pat_id:{payload.get('patient_id', '')}|"
        f"btg:{payload.get('is_emergency_override', False)}|"
        f"status:{payload.get('http_status', 200)}"
    )
    return hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()

def record_audit_event(
    db: Session,
    user_id: Optional[int],
    user_username: str,
    user_role: str,
    user_department: str,
    action: str,
    resource_type: str,
    client_ip: str = "127.0.0.1",
    resource_id: Optional[int] = None,
    patient_id: Optional[int] = None,
    patient_mrn: Optional[str] = None,
    is_emergency_override: bool = False,
    override_reason: Optional[str] = None,
    http_status: int = 200,
    risk_score_assigned: int = 0
) -> AuditLog:
    """
    Appends a new immutable audit record to the SHA-256 hash-chain.
    """
    # Fetch the latest audit log to obtain its hash
    last_log = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev_hash = last_log.record_hash if last_log else GENESIS_HASH

    now = datetime.now(timezone.utc)
    ts_str = now.strftime("%Y-%m-%d %H:%M:%S")

    import uuid
    evt_uuid = str(uuid.uuid4())

    payload = {
        "event_uuid": evt_uuid,
        "timestamp": ts_str,
        "user_username": user_username,
        "user_role": user_role,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id or "",
        "patient_id": patient_id or "",
        "is_emergency_override": is_emergency_override,
        "http_status": http_status
    }

    record_hash = compute_payload_hash(prev_hash, payload)

    audit_entry = AuditLog(
        event_uuid=evt_uuid,
        timestamp=now,
        user_id=user_id,
        user_username=user_username,
        user_role=user_role,
        user_department=user_department,
        client_ip=client_ip,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        patient_id=patient_id,
        patient_mrn=patient_mrn,
        is_emergency_override=is_emergency_override,
        override_reason=override_reason,
        http_status=http_status,
        risk_score_assigned=risk_score_assigned,
        prev_hash=prev_hash,
        record_hash=record_hash
    )

    db.add(audit_entry)
    db.commit()
    db.refresh(audit_entry)
    return audit_entry

def verify_blockchain_integrity(db: Session) -> Dict[str, Any]:
    """
    Audits the entire chain from Genesis block forward.
    Validates:
    1. Genesis block references GENESIS_HASH.
    2. Every block i references block i-1's record_hash.
    3. Recomputing the SHA-256 hash matches the stored record_hash.
    """
    logs = db.query(AuditLog).order_by(AuditLog.id.asc()).all()

    if not logs:
        return {
            "status": "VALID",
            "total_blocks": 0,
            "message": "Audit chain is empty. No blocks to verify.",
            "tampered": False
        }

    expected_prev = GENESIS_HASH

    for idx, log in enumerate(logs):
        # Check linkage
        if log.prev_hash != expected_prev:
            return {
                "status": "TAMPERED",
                "tampered": True,
                "broken_block_id": log.id,
                "broken_event_uuid": log.event_uuid,
                "error_type": "POINTER_MISMATCH",
                "message": f"Block #{log.id} prev_hash mismatch. Expected {expected_prev[:12]}..., got {log.prev_hash[:12]}...",
                "verified_blocks": idx,
                "total_blocks": len(logs)
            }

        # Check payload integrity
        if isinstance(log.timestamp, datetime):
            ts_str = log.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        else:
            ts_str = str(log.timestamp)[:19]

        payload = {
            "event_uuid": log.event_uuid,
            "timestamp": ts_str,
            "user_username": log.user_username,
            "user_role": log.user_role,
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id or "",
            "patient_id": log.patient_id or "",
            "is_emergency_override": log.is_emergency_override,
            "http_status": log.http_status
        }
        computed = compute_payload_hash(log.prev_hash, payload)
        if computed != log.record_hash:
            return {
                "status": "TAMPERED",
                "tampered": True,
                "broken_block_id": log.id,
                "broken_event_uuid": log.event_uuid,
                "error_type": "DATA_CORRUPTED",
                "message": f"Block #{log.id} data modified! Computed {computed[:12]}... != Stored {log.record_hash[:12]}...",
                "verified_blocks": idx,
                "total_blocks": len(logs)
            }

        expected_prev = log.record_hash

    return {
        "status": "VALID",
        "tampered": False,
        "total_blocks": len(logs),
        "latest_hash": expected_prev,
        "message": f"Cryptographic audit chain completely verified. All {len(logs)} blocks intact."
    }

def simulate_audit_tampering(db: Session, target_id: Optional[int] = None) -> Dict[str, Any]:
    """
    Demo/Judges feature: Maliciously modifies a random or specified audit log in the database
    to showcase immediate detection by the integrity verifier.
    """
    if target_id:
        log = db.query(AuditLog).filter(AuditLog.id == target_id).first()
    else:
        # Pick a middle block
        count = db.query(AuditLog).count()
        if count == 0:
            return {"success": False, "message": "No logs to tamper with."}
        mid = max(1, count // 2)
        log = db.query(AuditLog).filter(AuditLog.id == mid).first()

    if not log:
        return {"success": False, "message": "Target audit log not found."}

    original_action = log.action
    log.action = "TAMPERED_ACTION_EXPUNGED"
    db.commit()

    return {
        "success": True,
        "tampered_block_id": log.id,
        "event_uuid": log.event_uuid,
        "original_action": original_action,
        "modified_action": log.action,
        "message": f"Block #{log.id} action maliciously modified from '{original_action}' to '{log.action}'."
    }

