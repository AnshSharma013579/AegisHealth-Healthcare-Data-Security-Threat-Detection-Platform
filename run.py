import os
import sys
from pathlib import Path

# Add backend directory to path
ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.insert(0, str(BACKEND_DIR))

import uvicorn
from app.core.config import DB_PATH
from app.db.seed import seed_database

def main():
    print("=" * 75)
    print("  AEGISHEALTH: HEALTHCARE DATA SECURITY & THREAT DETECTION PLATFORM  ")
    print("  Cyber Arena 2026 - Problem Statement PS-21 Implementation          ")
    print("=" * 75)

    if not DB_PATH.exists():
        print("[!] Database not found. Initializing schema and synthetic dataset...")
        seed_database()
    else:
        print(f"[*] Connected to existing database: {DB_PATH}")

    print("\n[+] Demo Accounts Ready (Password: cyberarena2026 for all):")
    print("    • Attending Doctor: doctor_alice  (alice.smith@aegishealth.org)")
    print("    • Attending Doctor: doctor_frank  (frank.miller@aegishealth.org)")
    print("    • Floor Nurse:      nurse_bob     (bob.johnson@aegishealth.org)")
    print("    • Emergency Nurse:  nurse_carol   (carol.davis@aegishealth.org)")
    print("    • Lab Technician:   lab_david     (david.patel@aegishealth.org)")
    print("    • Billing Staff:    billing_eva   (eva.martinez@aegishealth.org)")
    print("    • Hospital Admin:   admin_grace   (grace.hopper@aegishealth.org)")
    print("    • Security Auditor: soc_analyst   (alex.vance@aegishealth.org)")
    print("    • Credentials File: DEFAULT_ACCOUNTS.txt")
    print("\n[+] Web Application: http://127.0.0.1:8000")
    print("[+] OpenAPI / Docs:  http://127.0.0.1:8000/docs")
    print("=" * 75)

    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    is_dev = os.environ.get("RENDER") is None and os.environ.get("CI") is None
    reload_flag = os.environ.get("RELOAD", "true" if is_dev else "false").lower() in ("true", "1")

    print(f"\n[+] Binding server to http://{host}:{port} (reload={reload_flag})...")
    uvicorn.run("app.main:app", host=host, port=port, reload=reload_flag, app_dir=str(BACKEND_DIR))

if __name__ == "__main__":
    main()

