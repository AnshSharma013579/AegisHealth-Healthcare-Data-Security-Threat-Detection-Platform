import pytest
import sys
from pathlib import Path

# Add backend directory to path
ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from fastapi.testclient import TestClient
from app.main import app
from app.db.database import SessionLocal
from app.db.models import User, Patient, AuditLog, SecurityAlert
from app.core.audit_chain import verify_blockchain_integrity, simulate_audit_tampering

client = TestClient(app)

def test_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "HEALTHY"

def test_auth_login():
    res = client.post("/api/auth/login", json={"username": "doctor_alice", "password": "cyberarena2026"})
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["user"]["role"] == "DOCTOR"
    assert data["user"]["department"] == "Cardiology"

def test_unauthorized_login_failure():
    res = client.post("/api/auth/login", json={"username": "doctor_alice", "password": "wrong_password"})
    assert res.status_code == 401

def test_blockchain_integrity_and_tampering():
    db = SessionLocal()
    try:
        # Verify initial intact chain
        check1 = verify_blockchain_integrity(db)
        assert check1["status"] == "VALID"
        assert check1["tampered"] is False

        # Tamper with an audit entry
        tamper_res = simulate_audit_tampering(db)
        assert tamper_res["success"] is True

        # Verify tamper is immediately flagged
        check2 = verify_blockchain_integrity(db)
        assert check2["status"] == "TAMPERED"
        assert check2["tampered"] is True
        assert check2["broken_block_id"] == tamper_res["tampered_block_id"]

        # Restore the record for subsequent tests
        log = db.query(AuditLog).filter(AuditLog.id == tamper_res["tampered_block_id"]).first()
        log.action = tamper_res["original_action"]
        db.commit()

        # Re-verify restored chain
        check3 = verify_blockchain_integrity(db)
        assert check3["status"] == "VALID"
    finally:
        db.close()

def test_rbac_doctor_access():
    # Login as Doctor Alice
    login_res = client.post("/api/auth/login", json={"username": "doctor_alice", "password": "cyberarena2026"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Fetch patient list
    patients_res = client.get("/api/patients", headers=headers)
    assert patients_res.status_code == 200
    patients = patients_res.json()
    assert len(patients) > 0

    # View first patient chart
    p_id = patients[0]["id"]
    chart_res = client.get(f"/api/patients/{p_id}", headers=headers)
    assert chart_res.status_code == 200
    chart_data = chart_res.json()
    assert "records" in chart_data

def test_break_the_glass_scenario():
    # Trigger BTG scenario
    res = client.post("/api/simulator/scenario/break_the_glass")
    assert res.status_code == 200
    data = res.json()
    assert data["outcome"] == "EMERGENCY CLEARANCE GRANTED"
    assert data["rule_code"] == "RULE-07"

def test_honeytoken_tripwire_scenario():
    # Trigger Honeytoken scenario
    res = client.post("/api/simulator/scenario/honeytoken_snoop")
    assert res.status_code == 200
    data = res.json()
    assert data["severity"] == "CRITICAL"
    assert data["risk_points_added"] == 100
    assert data["quarantine_status"] is True

def test_bulk_scraping_scenario():
    # Trigger Bulk Scraping scenario
    res = client.post("/api/simulator/scenario/bulk_scraping")
    assert res.status_code == 200
    data = res.json()
    assert data["records_probed"] >= 10
    assert data["alerts_triggered"] >= 1

def test_bulk_exfiltration_blocked():
    # Trigger Bulk Exfiltration scenario
    res = client.post("/api/simulator/scenario/bulk_exfiltration")
    assert res.status_code == 200
    data = res.json()
    assert data["rule_code"] == "RULE-06"
    assert data["severity"] == "CRITICAL"

def test_clinical_roles_denied_soc_and_audit():
    # Reset any quarantined users from previous attack tests
    client.post("/api/simulator/scenario/reset_all")

    # Verify clinical roles (Doctor, Nurse, Lab Tech, Billing) get 403 Forbidden on SOC & Audit endpoints
    clinical_users = ["doctor_alice", "nurse_bob", "lab_david", "billing_eva"]
    for username in clinical_users:
        login_res = client.post("/api/auth/login", json={"username": username, "password": "cyberarena2026"})
        assert login_res.status_code == 200
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # SOC Stats - MUST BE 403
        soc_res = client.get("/api/soc/stats", headers=headers)
        assert soc_res.status_code == 403, f"User {username} should NOT access SOC stats, got {soc_res.status_code}"

        # SOC Alerts - MUST BE 403
        alerts_res = client.get("/api/soc/alerts", headers=headers)
        assert alerts_res.status_code == 403, f"User {username} should NOT access SOC alerts, got {alerts_res.status_code}"

        # Audit Logs - MUST BE 403
        audit_res = client.get("/api/audit/logs", headers=headers)
        assert audit_res.status_code == 403, f"User {username} should NOT access Audit logs, got {audit_res.status_code}"

        # Audit Integrity Check - MUST BE 403
        integrity_res = client.get("/api/audit/verify-integrity", headers=headers)
        assert integrity_res.status_code == 403, f"User {username} should NOT verify audit integrity, got {integrity_res.status_code}"

def test_auditor_and_admin_allowed_soc_and_audit():
    # Verify Auditor and Admin get 200 OK on SOC and Audit endpoints
    privileged_users = ["soc_analyst", "admin_grace"]
    for username in privileged_users:
        login_res = client.post("/api/auth/login", json={"username": username, "password": "cyberarena2026"})
        assert login_res.status_code == 200
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # SOC Stats - MUST BE 200
        soc_res = client.get("/api/soc/stats", headers=headers)
        assert soc_res.status_code == 200, f"User {username} should access SOC stats, got {soc_res.status_code}"

        # SOC Alerts - MUST BE 200
        alerts_res = client.get("/api/soc/alerts", headers=headers)
        assert alerts_res.status_code == 200, f"User {username} should access SOC alerts, got {alerts_res.status_code}"

        # Audit Logs - MUST BE 200
        audit_res = client.get("/api/audit/logs", headers=headers)
        assert audit_res.status_code == 200, f"User {username} should access Audit logs, got {audit_res.status_code}"

        # Audit Integrity Check - MUST BE 200
        integrity_res = client.get("/api/audit/verify-integrity", headers=headers)
        assert integrity_res.status_code == 200, f"User {username} should verify audit integrity, got {integrity_res.status_code}"

def test_http_security_headers_compliance():
    """Validates HIPAA §164.312(e)(1), NIST SP 800-53 (SC-8, SC-13, SC-28), and OWASP Top 10 security headers."""
    res = client.get("/health")
    assert res.status_code == 200
    headers = res.headers

    # 1. Anti-Clickjacking
    assert headers.get("X-Frame-Options") == "DENY"

    # 2. Anti-MIME Sniffing
    assert headers.get("X-Content-Type-Options") == "nosniff"

    # 3. HSTS Strict Transport Security
    assert "Strict-Transport-Security" in headers
    assert "max-age=31536000" in headers["Strict-Transport-Security"]

    # 4. Content Security Policy
    assert "Content-Security-Policy" in headers
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]

    # 5. ePHI Cache-Control
    assert "no-store" in headers.get("Cache-Control", "")

    # 6. Compliance Frameworks Declaration
    assert "HIPAA-45CFR164" in headers.get("X-Compliance-Frameworks", "")
    assert "NIST-SP-800-53-Rev5" in headers.get("X-Compliance-Frameworks", "")

def test_automated_compliance_scan_endpoint():
    """Validates the live compliance scan endpoint across HIPAA, NIST, HITRUST, GDPR, and OWASP."""
    login_res = client.post("/api/auth/login", json={"username": "soc_analyst", "password": "cyberarena2026"})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/soc/compliance", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert data["overall_status"] == "COMPLIANT"
    assert data["compliance_score"] == 100
    assert data["total_controls"] == 10
    assert len(data["standards"]) == 5
    assert all(c["status"] == "PASS" for c in data["controls"])

def test_brute_force_rate_limiting_defense():
    """Validates NIST SP 800-53 (AC-7) and HIPAA §164.312(d) brute-force protection."""
    from app.api.auth import FAILED_LOGIN_ATTEMPTS
    FAILED_LOGIN_ATTEMPTS.clear()

    # Attempt 5 failed logins for an attacker identifier
    test_user = "brute_target_test"
    for _ in range(5):
        res = client.post("/api/auth/login", json={"username": test_user, "password": "wrong_password"})
        assert res.status_code == 401

    # 6th attempt should be blocked with HTTP 429
    blocked_res = client.post("/api/auth/login", json={"username": test_user, "password": "wrong_password"})
    assert blocked_res.status_code == 429
    assert "Excessive failed authentication attempts" in blocked_res.json()["detail"]

    # Clear rate limiter state after test so subsequent tests have a clean client IP
    FAILED_LOGIN_ATTEMPTS.clear()

def test_appointments_rbac_billing_and_admin_allowed():
    """Validates that BILLING and ADMIN roles can create, update, and remove patient appointments."""
    # 1. Login as Billing staff (Eva Martinez)
    login_res = client.post("/api/auth/login", json={"username": "billing_eva", "password": "cyberarena2026"})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Get first patient
    patients_res = client.get("/api/patients", headers=headers)
    assert patients_res.status_code == 200
    patient_id = patients_res.json()[0]["id"]

    # 3. Schedule new appointment
    apt_payload = {
        "date": "2026-12-01",
        "time": "14:30",
        "department": "Cardiology",
        "staff": "Dr. Alice Smith",
        "purpose": "Routine follow-up echocardiogram",
        "status": "SCHEDULED"
    }
    create_res = client.post(f"/api/patients/{patient_id}/appointments", json=apt_payload, headers=headers)
    assert create_res.status_code == 200
    created_apt = create_res.json()["appointment"]
    apt_id = created_apt["id"]
    assert created_apt["purpose"] == apt_payload["purpose"]
    assert created_apt["status"] == "SCHEDULED"

    # 4. Update appointment status to CONFIRMED
    update_res = client.put(f"/api/patients/{patient_id}/appointments/{apt_id}", json={"status": "CONFIRMED"}, headers=headers)
    assert update_res.status_code == 200
    assert update_res.json()["appointment"]["status"] == "CONFIRMED"

    # 5. Cancel / Delete appointment
    delete_res = client.delete(f"/api/patients/{patient_id}/appointments/{apt_id}", headers=headers)
    assert delete_res.status_code == 200
    assert "removed successfully" in delete_res.json()["message"]

def test_appointments_rbac_non_billing_roles_forbidden():
    """Validates that non-billing clinical roles (e.g. Doctor, Nurse) cannot create, update, or remove appointments."""
    # 1. Login as Doctor Alice
    login_res = client.post("/api/auth/login", json={"username": "doctor_alice", "password": "cyberarena2026"})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    patient_id = 1
    apt_payload = {
        "date": "2026-12-05",
        "time": "10:00",
        "department": "Cardiology",
        "staff": "Dr. Alice Smith",
        "purpose": "Unauthorized Doctor attempt to schedule",
        "status": "SCHEDULED"
    }

    # 2. Attempt to create appointment -> Expect 403 Forbidden
    create_res = client.post(f"/api/patients/{patient_id}/appointments", json=apt_payload, headers=headers)
    assert create_res.status_code == 403
    assert "is not authorized to schedule appointments" in create_res.json()["detail"]

    # 3. Attempt to update appointment -> Expect 403 Forbidden
    update_res = client.put(f"/api/patients/{patient_id}/appointments/APT-999999", json={"status": "CANCELLED"}, headers=headers)
    assert update_res.status_code == 403
    assert "is not authorized to update appointments" in update_res.json()["detail"]

    # 4. Attempt to delete appointment -> Expect 403 Forbidden
    delete_res = client.delete(f"/api/patients/{patient_id}/appointments/APT-999999", headers=headers)
    assert delete_res.status_code == 403
    assert "is not authorized to remove appointments" in delete_res.json()["detail"]

    # 5. Doctor CAN read appointments via directory and detail
    read_res = client.get("/api/patients", headers=headers)
    assert read_res.status_code == 200
    assert "appointments" in read_res.json()[0]

if __name__ == "__main__":
    print("[*] Running automated security verification test suite...")
    pytest.main(["-v", __file__])


