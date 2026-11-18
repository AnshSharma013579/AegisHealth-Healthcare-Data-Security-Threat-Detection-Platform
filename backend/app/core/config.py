import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = DATA_DIR / "aegishealth.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

SECRET_KEY = os.getenv("SECRET_KEY", "aegis-cyberarena-2026-supersecret-jwt-key-928471049281")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12  # 12-hour session

# Detection Rule Thresholds
RULE_CONFIG = {
    "BULK_VIEW_WINDOW_SEC": 60,
    "BULK_VIEW_THRESHOLD": 10,  # >= 10 unique patients in 60s
    "DENIED_WINDOW_SEC": 180,
    "DENIED_THRESHOLD": 3,      # >= 3 denied access in 3m
    "SHIFT_GRACE_MINUTES": 30,  # 30 mins grace window
    "OFF_HOURS_VIOLATION_HOURS": 2.0,
    "EXFILTRATION_EXPORT_LIMIT": 5,
}

# Genesis Hash for Tamper-Evident SHA-256 Audit Chain
GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

