import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, Date, ForeignKey
)
from sqlalchemy.orm import relationship
from app.db.database import Base

def utcnow():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=False)
    role = Column(String(30), nullable=False)  # DOCTOR, NURSE, LAB_TECH, BILLING, ADMIN, AUDITOR
    department = Column(String(50), nullable=False)  # Cardiology, Oncology, Emergency, Pediatrics, Lab, Billing, Security
    shift_start = Column(String(5), default="08:00")  # "HH:MM"
    shift_end = Column(String(5), default="17:00")    # "HH:MM"
    current_risk_score = Column(Integer, default=0)
    is_quarantined = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)

    # Relationships
    authored_records = relationship("ClinicalRecord", back_populates="author", foreign_keys="ClinicalRecord.author_id")
    assignments = relationship("PatientAssignment", back_populates="staff")

class Patient(Base):
    __tablename__ = "patients"

    id = Column(Integer, primary_key=True, index=True)
    mrn = Column(String(30), unique=True, index=True, nullable=False)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    dob = Column(Date, nullable=False)
    gender = Column(String(10), nullable=False)
    department = Column(String(50), nullable=False)
    ward_room = Column(String(50), nullable=False)
    attending_doctor_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    is_vip = Column(Boolean, default=False)
    is_honeytoken = Column(Boolean, default=False)  # Decoy tripwire record
    appointments = Column(Text, default="[]", nullable=True)
    created_at = Column(DateTime, default=utcnow)

    # Relationships
    records = relationship("ClinicalRecord", back_populates="patient", cascade="all, delete-orphan")
    assignments = relationship("PatientAssignment", back_populates="patient", cascade="all, delete-orphan")

class ClinicalRecord(Base):
    __tablename__ = "clinical_records"

    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("patients.id"), nullable=False, index=True)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    record_type = Column(String(30), nullable=False)  # vitals, clinical_notes, prescription, lab_result, billing
    title = Column(String(150), nullable=False)
    content = Column(Text, nullable=False)
    sensitivity_level = Column(String(20), default="standard")  # standard, restricted, confidential
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    # Relationships
    patient = relationship("Patient", back_populates="records")
    author = relationship("User", back_populates="authored_records", foreign_keys=[author_id])

class PatientAssignment(Base):
    __tablename__ = "patient_assignments"

    id = Column(Integer, primary_key=True, index=True)
    staff_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    patient_id = Column(Integer, ForeignKey("patients.id"), nullable=False)
    care_role = Column(String(50), nullable=False)  # PRIMARY_MD, FLOOR_NURSE, CONSULTANT
    assigned_at = Column(DateTime, default=utcnow)
    is_active = Column(Boolean, default=True)

    staff = relationship("User", back_populates="assignments")
    patient = relationship("Patient", back_populates="assignments")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_uuid = Column(String(36), default=lambda: str(uuid.uuid4()), unique=True, index=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
    user_id = Column(Integer, nullable=True)
    user_username = Column(String(50), nullable=False)
    user_role = Column(String(30), nullable=False)
    user_department = Column(String(50), nullable=False)
    client_ip = Column(String(50), default="127.0.0.1")
    action = Column(String(30), nullable=False)  # LOGIN, LOGOUT, VIEW_RECORD, EDIT_RECORD, CREATE_RECORD, EXPORT_RECORDS, ACCESS_DENIED, BREAK_THE_GLASS, HONEYTOKEN_TRIGGER
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(Integer, nullable=True)
    patient_id = Column(Integer, nullable=True)
    patient_mrn = Column(String(50), nullable=True)
    is_emergency_override = Column(Boolean, default=False)
    override_reason = Column(Text, nullable=True)
    http_status = Column(Integer, default=200)
    risk_score_assigned = Column(Integer, default=0)
    prev_hash = Column(String(64), nullable=False)
    record_hash = Column(String(64), nullable=False)

class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_uuid = Column(String(36), default=lambda: str(uuid.uuid4()), unique=True, index=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
    rule_code = Column(String(20), nullable=False)  # RULE-01 to RULE-07
    rule_name = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    user_id = Column(Integer, nullable=True)
    user_username = Column(String(50), nullable=False)
    patient_id = Column(Integer, nullable=True)
    patient_mrn = Column(String(50), nullable=True)
    risk_score_delta = Column(Integer, default=0)
    description = Column(Text, nullable=False)
    context_json = Column(Text, default="{}")
    status = Column(String(20), default="ACTIVE")  # ACTIVE, ACKNOWLEDGED, RESOLVED

