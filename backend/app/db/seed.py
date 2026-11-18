import random
import sys
from pathlib import Path

# Add backend directory to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from datetime import datetime, date, timedelta, timezone
from faker import Faker
from app.db.database import SessionLocal, engine, Base
from app.db.models import User, Patient, ClinicalRecord, PatientAssignment, AuditLog, SecurityAlert
from app.core.security import hash_password
from app.core.audit_chain import record_audit_event

fake = Faker()
Faker.seed(42)
random.seed(42)

DEPARTMENTS = ["Cardiology", "Oncology", "Emergency", "Pediatrics", "Neurology", "Orthopedics"]

DIAGNOSES = [
    ("I21.9", "Acute Myocardial Infarction, unspecified", "Cardiology"),
    ("I50.9", "Heart Failure, unspecified", "Cardiology"),
    ("I10", "Essential (primary) Hypertension", "Cardiology"),
    ("C50.919", "Malignant neoplasm of unspecified site of breast", "Oncology"),
    ("C34.90", "Malignant neoplasm of unspecified part of bronchus or lung", "Oncology"),
    ("R07.9", "Chest pain, unspecified", "Emergency"),
    ("S06.0X0A", "Concussion without loss of consciousness, initial encounter", "Emergency"),
    ("J45.909", "Unspecified asthma, uncomplicated", "Pediatrics"),
    ("E11.9", "Type 2 diabetes mellitus without complications", "Cardiology"),
    ("G43.909", "Migraine, unspecified, not intractable", "Neurology"),
    ("S82.001A", "Fracture of patella, right knee", "Orthopedics")
]

MEDICATIONS = [
    ("Atorvastatin 20mg", "Once daily at bedtime for hyperlipidemia"),
    ("Lisinopril 10mg", "Once daily orally for blood pressure control"),
    ("Metoprolol Tartrate 25mg", "Twice daily with meals for arrhythmia control"),
    ("Metformin 500mg", "Twice daily with meals for glycemic regulation"),
    ("Amoxicillin 500mg", "Three times daily for 7 days for respiratory infection"),
    ("Aspirin 81mg", "Once daily enteric coated anti-platelet therapy"),
    ("Albuterol Inhaler 90mcg", "2 puffs every 4-6 hours PRN wheezing")
]

LAB_TESTS = [
    ("Complete Blood Count (CBC)", "WBC: 6.8 K/uL, RBC: 4.75 M/uL, Hgb: 14.2 g/dL, Plt: 245 K/uL. Normal limits."),
    ("Comprehensive Metabolic Panel (CMP)", "Na: 140 mEq/L, K: 4.1 mEq/L, BUN: 14 mg/dL, Creatinine: 0.9 mg/dL, Glucose: 98 mg/dL. Normal renal/electrolyte function."),
    ("Troponin I Cardiac Biomarker", "<0.01 ng/mL. No acute myocardial injury detected."),
    ("Lipid Panel Profile", "Total Cholesterol: 195 mg/dL, HDL: 48 mg/dL, LDL: 118 mg/dL, Triglycerides: 145 mg/dL."),
    ("Hemoglobin A1c", "5.8% (Target < 7.0%). Well-controlled baseline."),
    ("12-Lead Electrocardiogram (ECG)", "Normal sinus rhythm, rate 72 bpm, normal axis, no acute ST-T changes.")
]

def seed_database():
    """Seeds the database with users, patients, clinical records, honey-tokens, and initial audit entries."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    default_pw_hash = hash_password("cyberarena2026")

    print("[*] Seeding staff accounts...")
    users_data = [
        User(username="doctor_alice", email="alice.smith@aegishealth.org", hashed_password=default_pw_hash, full_name="Dr. Alice Smith, MD", role="DOCTOR", department="Cardiology", shift_start="08:00", shift_end="17:00"),
        User(username="doctor_frank", email="frank.miller@aegishealth.org", hashed_password=default_pw_hash, full_name="Dr. Frank Miller, MD", role="DOCTOR", department="Oncology", shift_start="08:00", shift_end="17:00"),
        User(username="nurse_bob", email="bob.johnson@aegishealth.org", hashed_password=default_pw_hash, full_name="Nurse Bob Johnson, RN", role="NURSE", department="Cardiology", shift_start="07:00", shift_end="15:30"),
        User(username="nurse_carol", email="carol.davis@aegishealth.org", hashed_password=default_pw_hash, full_name="Nurse Carol Davis, RN", role="NURSE", department="Emergency", shift_start="15:00", shift_end="23:30"),
        User(username="lab_david", email="david.patel@aegishealth.org", hashed_password=default_pw_hash, full_name="David Patel, MLS", role="LAB_TECH", department="Lab", shift_start="09:00", shift_end="17:00"),
        User(username="billing_eva", email="eva.martinez@aegishealth.org", hashed_password=default_pw_hash, full_name="Eva Martinez", role="BILLING", department="Billing", shift_start="08:30", shift_end="16:30"),
        User(username="admin_grace", email="grace.hopper@aegishealth.org", hashed_password=default_pw_hash, full_name="Grace Hopper, VP Ops", role="ADMIN", department="Administration", shift_start="08:00", shift_end="18:00"),
        User(username="soc_analyst", email="alex.vance@aegishealth.org", hashed_password=default_pw_hash, full_name="Alex Vance, CISSP", role="AUDITOR", department="Security", shift_start="00:00", shift_end="23:59"),
    ]
    for u in users_data:
        db.add(u)
    db.commit()

    # Re-fetch users for foreign keys
    doctors = db.query(User).filter(User.role == "DOCTOR").all()
    nurses = db.query(User).filter(User.role == "NURSE").all()
    alice = db.query(User).filter(User.username == "doctor_alice").first()
    bob = db.query(User).filter(User.username == "nurse_bob").first()
    david = db.query(User).filter(User.username == "lab_david").first()

    print("[*] Seeding 50 realistic patients & clinical records...")
    patients_list = []

    # 1. Add Special VIP Patient (Real VIP)
    vip_pat = Patient(
        mrn="MRN-VIP-9001",
        first_name="Sterling",
        last_name="Cross",
        dob=date(1968, 5, 14),
        gender="Male",
        department="Cardiology",
        ward_room="Executive Wing Suite 401",
        attending_doctor_id=alice.id,
        is_vip=True,
        is_honeytoken=False,
        appointments='[{"id": "APT-901", "date": "2026-11-22", "time": "10:00 AM", "department": "Cardiology", "staff": "Dr. Alice Smith, MD", "purpose": "VIP Executive Cardiovascular Re-Evaluation", "status": "Scheduled", "created_by": "eva.martinez@aegishealth.org"}]'
    )
    db.add(vip_pat)
    db.commit()
    db.refresh(vip_pat)
    patients_list.append(vip_pat)

    # 2. Add Honey-Token Trap Record (CRITICAL Tripwire)
    honey_pat = Patient(
        mrn="MRN-HONEY-9999",
        first_name="Elena",
        last_name="Vance",
        dob=date(1982, 11, 23),
        gender="Female",
        department="Oncology",
        ward_room="Private Pavilion 102",
        attending_doctor_id=None,
        is_vip=True,
        is_honeytoken=True  # DECOY TRIPWIRE
    )
    db.add(honey_pat)
    db.commit()
    db.refresh(honey_pat)
    patients_list.append(honey_pat)

    # 3. Add 48 standard synthetic patients across departments
    for i in range(1, 49):
        dept = random.choice(DEPARTMENTS)
        gender = random.choice(["Male", "Female"])
        first_name = fake.first_name_male() if gender == "Male" else fake.first_name_female()
        last_name = fake.last_name()
        dob = fake.date_of_birth(minimum_age=18, maximum_age=85)
        room = f"{dept[:4].upper()}-{random.randint(101, 350)}"
        doc = random.choice(doctors)

        p = Patient(
            mrn=f"MRN-2026-{1000 + i}",
            first_name=first_name,
            last_name=last_name,
            dob=dob,
            gender=gender,
            department=dept,
            ward_room=room,
            attending_doctor_id=doc.id,
            is_vip=False,
            is_honeytoken=False
        )
        db.add(p)
        patients_list.append(p)

    db.commit()

    # Re-fetch all patients
    all_patients = db.query(Patient).all()

    print("[*] Generating clinical notes, vitals, prescriptions, and lab records...")
    for p in all_patients:
        # Care assignment for doctor and nurse
        if p.department == "Cardiology":
            db.add(PatientAssignment(staff_id=alice.id, patient_id=p.id, care_role="PRIMARY_MD"))
            db.add(PatientAssignment(staff_id=bob.id, patient_id=p.id, care_role="FLOOR_NURSE"))

        # Add vitals
        sys = random.randint(110, 145)
        dia = random.randint(70, 92)
        hr = random.randint(60, 95)
        spo2 = random.randint(95, 100)
        temp = round(random.uniform(97.8, 99.2), 1)

        vitals_rec = ClinicalRecord(
            patient_id=p.id,
            author_id=bob.id if p.department == "Cardiology" else alice.id,
            record_type="vitals",
            title=f"Routine Bedside Vitals - Ward {p.ward_room}",
            content=f"Blood Pressure: {sys}/{dia} mmHg | Heart Rate: {hr} bpm | SpO2: {spo2}% on room air | Temp: {temp}°F | Resp: 16/min.",
            sensitivity_level="standard"
        )
        db.add(vitals_rec)

        # Add Diagnosis & Clinical Notes
        diag = random.choice([d for d in DIAGNOSES if d[2] == p.department] or [DIAGNOSES[0]])
        notes_rec = ClinicalRecord(
            patient_id=p.id,
            author_id=alice.id if p.attending_doctor_id == alice.id else doctors[0].id,
            record_type="clinical_notes",
            title=f"Clinical Evaluation: {diag[1]} ({diag[0]})",
            content=f"Patient presents for follow-up of {diag[1]}. Alert and oriented x4. Cardiovascular exam reveals regular rate and rhythm without murmurs. Lungs clear to auscultation bilaterally. Plan: Continue current medical management, repeat metabolic panel in 4 weeks.",
            sensitivity_level="confidential" if p.is_vip else "standard"
        )
        db.add(notes_rec)

        # Add Prescription
        med = random.choice(MEDICATIONS)
        rx_rec = ClinicalRecord(
            patient_id=p.id,
            author_id=alice.id if p.attending_doctor_id == alice.id else doctors[0].id,
            record_type="prescription",
            title=f"Active Prescription: {med[0]}",
            content=f"Rx: {med[0]}\nSig: {med[1]}\nRefills: 3\nDispense: 30-day supply with safety cap.",
            sensitivity_level="standard"
        )
        db.add(rx_rec)

        # Add Lab Result
        lab = random.choice(LAB_TESTS)
        lab_rec = ClinicalRecord(
            patient_id=p.id,
            author_id=david.id,
            record_type="lab_result",
            title=f"Diagnostic Report: {lab[0]}",
            content=f"Laboratory specimen collected and processed under CLIA protocol.\nFindings: {lab[1]}\nSigned: David Patel, MLS (Lab Sciences)",
            sensitivity_level="standard"
        )
        db.add(lab_rec)

        # Add Billing Invoice
        cost = random.randint(350, 4800)
        bill_rec = ClinicalRecord(
            patient_id=p.id,
            author_id=db.query(User).filter(User.username == "billing_eva").first().id,
            record_type="billing",
            title=f"Hospital Statement & Insurance Claim #{random.randint(100000, 999999)}",
            content=f"Inpatient Stay / Observation Services\nTotal Billed: ${cost}.00\nPrimary Payer: BlueCross Advantage (Policy #BCA-{random.randint(10000, 99999)})\nPatient Copay Due: $50.00\nStatus: Processed & Approved.",
            sensitivity_level="standard"
        )
        db.add(bill_rec)

    db.commit()

    print("[*] Initializing Cryptographic Audit Chain with Genesis Block...")
    genesis_event = record_audit_event(
        db=db,
        user_id=None,
        user_username="SYSTEM_INIT",
        user_role="SYSTEM",
        user_department="INFRASTRUCTURE",
        action="SYSTEM_BOOTSTRAP",
        resource_type="AUDIT_CHAIN_GENESIS",
        http_status=200,
        risk_score_assigned=0
    )
    print(f"[*] Genesis block created: Hash = {genesis_event.record_hash[:16]}... Prev = {genesis_event.prev_hash}")

    db.close()
    print("[+] Database successfully seeded with 50 patients, medical records, and genesis ledger!")

if __name__ == "__main__":
    seed_database()
