# AegisHealth: Healthcare Data Security & Threat Detection Platform
### Cyber Arena 2026 — Problem Statement PS-21 Implementation

> **Critical Infrastructure & Public Safety**  
> **PS-21: Healthcare Data Security and Unauthorized Medical Record Access Detection**  
> Hospitals maintain sensitive Electronic Health Records (EHR) containing medical histories, prescriptions, diagnostic reports, and patient identifiers. Unauthorized access, privilege escalation, or inappropriate bulk viewing violates patient privacy. This system enforces strict access control and detects suspicious record access patterns in real time.

---

## 🌟 Key Innovations & Deliverables

| Deliverable | Implementation in AegisHealth | Hackathon Criteria |
| :--- | :--- | :--- |
| **1. Realistic EHR Environment** | 50+ synthetic patients across 6 clinical departments with realistic ICD-10 diagnoses, medications, bedside vitals, lab reports, and billing statements. | **Technical Depth (25%)** |
| **2. Dual RBAC + ABAC Access Control** | Enforces role-based permissions (Doctor, Nurse, Lab Tech, Billing, Admin, Auditor) combined with dynamic attribute checks (department match, active care assignment, shift schedules, sensitivity levels). | **Technical Depth (25%)** |
| **3. Break-the-Glass (BTG) Protocol** | Clinical emergency override allowing physicians/nurses to access locked records in life-critical situations with mandatory justification and real-time SOC alerting. | **Innovation (25%)** |
| **4. Honey-Token Decoy Tripwires** | Synthetic VIP decoy patient records (`is_honeytoken=True`) placed in the database. Any unauthorized access triggers an immediate CRITICAL severity tripwire and auto-quarantines the user. | **Innovation (25%)** |
| **5. Tamper-Evident SHA-256 Audit Chain** | Merkle/blockchain-inspired ledger chaining every single interaction (`hash_i = SHA-256(prev_hash + log_payload)`). Built-in verification detects database tampering down to the exact corrupted block. | **Technical Depth (25%)** |
| **6. Real-Time UEBA Threat Engine** | Sliding-window behavioral analysis evaluating 7 security threat rules with dynamic risk score accumulation ($0-100$) and automatic quarantine thresholds. | **Innovation (25%)** |
| **7. 1-Click Attack Simulator for Judges** | Built-in scenario injection suite allowing judges to trigger legitimate workflows vs. insider threats (Bulk Scraping, Honey-Token Trip, Shift Anomalies, Probing) with one click. | **Presentation & Demo (25%)** |

---

## ⚡ Quick Start (Single-Command Launch)

### Prerequisites
- Python 3.12+ (uv or standard pip)

### 1. Launch Platform
```bash
python run.py
```
*The launcher automatically initializes the SQLite WAL database, generates the synthetic patient dataset and honey-token decoys, computes the cryptographic genesis block, and starts the server on port 8000.*

- **Web Application Portal:** [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive OpenAPI Docs:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 👥 Demo Staff Credentials

All accounts use the password: `cyberarena2026`  
Log in via the unified login screen using hospital email or username. Default account credentials are saved in [DEFAULT_ACCOUNTS.txt](file:///d:/ctf/DEFAULT_ACCOUNTS.txt).

| Username | Role | Department | Shift | Care Responsibility |
| :--- | :--- | :--- | :--- | :--- |
| `doctor_alice` | **DOCTOR** | Cardiology | 08:00 - 17:00 | Attending Cardiologist (full clinical notes & Rx) |
| `doctor_frank` | **DOCTOR** | Oncology | 08:00 - 17:00 | Attending Oncologist |
| `nurse_bob` | **NURSE** | Cardiology | 07:00 - 15:30 | Ward Nurse (vitals, prescriptions, standard notes) |
| `nurse_carol` | **NURSE** | Emergency | 15:00 - 23:30 | ER Triage Nurse |
| `lab_david` | **LAB_TECH** | Laboratory | 09:00 - 17:00 | Diagnostic specimen processing & lab uploads |
| `billing_eva` | **BILLING** | Billing / Reception | 08:30 - 16:30 | Demographics, appointments, billing statements |
| `admin_grace` | **ADMIN** | Administration | 08:00 - 18:00 | User roster & departmental management |
| `soc_analyst` | **AUDITOR** | Security SOC | 00:00 - 23:59 | Real-time threat monitoring & audit verification |

---

## 📜 Regulatory Standards Compliance (HIPAA, NIST, HITRUST, GDPR, OWASP)

AegisHealth is built from the ground up to achieve **100% compliance** across major healthcare security and privacy regulations. Full technical documentation, legal citations, and audit evidence are detailed in [COMPLIANCE.md](file:///d:/ctf/COMPLIANCE.md).

- **HIPAA Security & Privacy Rules (45 CFR §164.308 / §164.312 / §164.502):**
  - §164.312(a)(1) Access Control & Segregation of Duties (Clinical vs SOC)
  - §164.312(a)(2)(ii) Emergency Break-The-Glass Protocol
  - §164.312(a)(2)(iii) Inactivity Auto-Lock Timer (15-min timeout with 60s warning)
  - §164.312(b) Audit Controls & Non-Repudiation Logging
  - §164.312(c)(1) Data Integrity via SHA-256 Merkle Hash-Chain
  - §164.312(e)(1) Transmission Security & Defensive HTTP Headers
  - §164.502(b) Minimum Necessary PHI Filtering
- **NIST SP 800-53 Rev. 5 & SP 800-66 Rev. 2:** AC-2, AC-3, AC-6, AC-7, AC-11, AU-2, AU-3, AU-9, IA-5, SC-8, SC-28, SI-4
- **HITRUST CSF v11.2:** Controls 01.b, 01.c, 02.b, 03.e
- **GDPR (Regulation EU 2016/679):** Articles 25, 32, 33 (Data Protection by Design & Real-Time Breach Notification)
- **OWASP API Security Top 10 (2023):** BOLA, Broken Authentication, Broken Object Property, Rate Limiting, BFLA, Security Misconfiguration

---

## 📅 Appointments & Reception Scheduling (Billing & Admin)
- **Reception & Billing Scheduling:** Authorized `BILLING` and `ADMIN` personnel can add, reschedule, and cancel patient appointments directly in the clinical chart.
- **Appointments Column in Directory:** Live appointment badges display next to each patient record in the directory.
- **Cryptographic Auditability:** Every appointment creation, modification, and cancellation is permanently hashed into the blockchain ledger.
- **Clinical Role Least Privilege:** Clinical staff (`DOCTOR`, `NURSE`, `LAB_TECH`, `AUDITOR`) have read-only visibility into appointments, preventing unauthorized schedule modifications.

---

## 🛡️ Anomaly Detection Rule Specifications

```
+-----------+-----------------------------------+----------+-------------+-------------------------------------------------------------+
| Rule ID   | Threat Pattern                    | Severity | Risk Points | Detection Criteria & Logic                                  |
+-----------+-----------------------------------+----------+-------------+-------------------------------------------------------------+
| RULE-01   | Bulk Record Scraping              | HIGH     | +40         | >= 10 unique patient record views within 60-second window.  |
| RULE-02   | Department / Scope Mismatch       | MEDIUM   | +25         | Staff views patient outside department without assignment.  |
| RULE-03   | Honey-Token / VIP Snooping        | CRITICAL | +100        | Any access to record flagged is_honeytoken=True.            |
| RULE-04   | Off-Hours / Shift Anomaly         | MEDIUM   | +20         | Access occurs >= 2 hours outside active shift schedule.     |
| RULE-05   | Repeated Access Denials (Probing) | HIGH     | +35         | >= 3 ACCESS_DENIED events within 3-minute window.           |
| RULE-06   | Unauthorized Bulk Exfiltration    | CRITICAL | +60         | Non-Auditor triggers record export or batch download.       |
| RULE-07   | Break-The-Glass Protocol Review   | LOW/MED  | +15         | Emergency override invoked; flagged for mandatory SOC audit.|
+-----------+-----------------------------------+----------+-------------+-------------------------------------------------------------+
```

### Dynamic Threat Scoring Formula
$$R(u, t) = \min\left(100, \sum_{k \in \text{incidents}} \Delta R_k \cdot \gamma^{\Delta t_k}\right)$$
- If $R(u, t) \ge 85$ or upon any `CRITICAL` alert, the user account is automatically quarantined.

---

## 🎯 Live Pitch & Judge Demo Walkthrough (5 Minutes)

### Step 1: Normal Clinical Operations (EHR Portal)
1. Switch to **Dr. Alice (Cardiology)** via the top role bar.
2. Filter by **Cardiology** ward and click **View Chart** on a cardiology patient.
3. Observe full access: vitals, ECG diagnostics, clinical progress notes, and active medications.
4. Risk score remains **0** (Green).

### Step 2: Attribute-Based Access Control (ABAC) in Action
1. Switch to **Billing Eva (Billing)**.
2. Attempt to open a patient's chart. Notice that clinical notes, prescriptions, and lab results are masked or restricted, while billing statements remain visible.

### Step 3: Break-The-Glass (BTG) Emergency Workflow
1. Switch to **Dr. Frank (Oncology)** and try to view an Emergency department patient.
2. Notice the access restriction. Click the **Break-The-Glass** button.
3. Input emergency reason: *"Cardiac arrest in triage; urgent allergy record required"*.
4. Emergency clearance is granted, audit event is chained, and the SOC is immediately notified!

### Step 4: The Attack Simulator (1-Click Threat Injections)
Switch to the **Attack Simulator** tab:
1. **Click "Simulate Bulk Scraping":** Nurse Bob queries 12 records in 1 second. Watch **RULE-01** fire in the live alert stream, adding +40 risk.
2. **Click "Trip Honey-Token Trap":** Decoy VIP "Ambassador Elena Vance" is accessed. Instant **RULE-03 CRITICAL Alert** fires, risk spikes to 100, and user is quarantined on the spot!
3. **Click "Simulate Exfiltration":** Staff attempts bulk export without clearance. **RULE-06 CRITICAL Alert** blocks exfiltration.

### Step 5: Cryptographic Audit Ledger & Tamper Verification
1. Navigate to the **Cryptographic Ledger** tab.
2. Click **"Verify Audit Blockchain"**: Green banner confirms all blocks are 100% intact against the SHA-256 genesis root.
3. Click **"Simulate DB Tampering (Demo)"**: Maliciously alters a historical database row.
4. Click **"Verify Audit Blockchain"** again: Watch the system turn flashing red, immediately identifying the exact corrupted block ID and payload hash mismatch!

---

## 🧪 Automated Test Suite
To run all automated security and cryptographic unit tests:
```bash
pytest -v tests/test_security.py
```
*(Verifies RBAC boundaries, ABAC restrictions, Break-The-Glass, Honey-Token tripwires, and SHA-256 hash chaining).*

