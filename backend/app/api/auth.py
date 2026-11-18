from typing import Optional, Dict, List
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import User
from app.core.security import verify_password, create_access_token
from app.core.audit_chain import record_audit_event
from app.services.rbac_abac import get_current_user

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

# In-memory sliding window rate limiter for brute-force protection (NIST SP 800-53 AC-7, HIPAA §164.312(d))
FAILED_LOGIN_ATTEMPTS: Dict[str, List[datetime]] = {}
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW_SECONDS = 180  # 3 minutes

def is_rate_limited(key: str) -> bool:
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=LOCKOUT_WINDOW_SECONDS)
    attempts = [t for t in FAILED_LOGIN_ATTEMPTS.get(key, []) if t > cutoff]
    FAILED_LOGIN_ATTEMPTS[key] = attempts
    return len(attempts) >= MAX_FAILED_ATTEMPTS

def record_failed_attempt(key: str):
    now = datetime.now(timezone.utc)
    if key not in FAILED_LOGIN_ATTEMPTS:
        FAILED_LOGIN_ATTEMPTS[key] = []
    FAILED_LOGIN_ATTEMPTS[key].append(now)

def clear_failed_attempts(key: str):
    FAILED_LOGIN_ATTEMPTS.pop(key, None)

class LoginRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    password: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    full_name: str
    role: str
    department: str
    shift_start: str
    shift_end: str
    current_risk_score: int
    is_quarantined: bool

@router.post("/login")
async def login(req: LoginRequest, response: Response, request: Request, db: Session = Depends(get_db)):
    login_id = (req.username or req.email or "").strip()
    if not login_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email is required."
        )

    client_ip = request.client.host if request.client else "127.0.0.1"

    # Enforce Brute-Force Rate Limiting (NIST SP 800-53 AC-7, HIPAA §164.312(d))
    if is_rate_limited(login_id) or is_rate_limited(client_ip):
        record_audit_event(
            db=db,
            user_id=None,
            user_username=login_id,
            user_role="UNKNOWN",
            user_department="UNKNOWN",
            client_ip=client_ip,
            action="LOGIN_BRUTE_FORCE_THROTTLED",
            resource_type="auth_session",
            http_status=429,
            risk_score_assigned=35
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="SECURITY ALERT: Excessive failed authentication attempts. Account temporarily locked to prevent brute-force attacks in compliance with NIST SP 800-53 (AC-7) & HIPAA §164.312(d). Please retry in 3 minutes."
        )

    # Allow login with either username or email address
    user = db.query(User).filter(
        (User.username == login_id) | (User.email == login_id)
    ).first()

    if not user or not verify_password(req.password, user.hashed_password):
        # Record failed attempt for rate limiting
        record_failed_attempt(login_id)
        record_failed_attempt(client_ip)

        # Record failed login in immutable audit log
        record_audit_event(
            db=db,
            user_id=user.id if user else None,
            user_username=user.username if user else login_id,
            user_role="UNKNOWN",
            user_department="UNKNOWN",
            client_ip=client_ip,
            action="LOGIN_FAILED",
            resource_type="auth_session",
            http_status=401,
            risk_score_assigned=10
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username, email, or password."
        )

    # Login succeeded - clear failed attempt counters
    clear_failed_attempts(login_id)
    clear_failed_attempts(user.username)
    clear_failed_attempts(client_ip)

    if user.is_quarantined:
        record_audit_event(
            db=db,
            user_id=user.id,
            user_username=user.username,
            user_role=user.role,
            user_department=user.department,
            client_ip=client_ip,
            action="LOGIN_BLOCKED_QUARANTINE",
            resource_type="auth_session",
            http_status=403,
            risk_score_assigned=20
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="SECURITY ALERT: User account is actively quarantined due to high-risk behavioral anomalies."
        )

    # Issue JWT
    token_data = {
        "sub": user.username,
        "user_id": user.id,
        "role": user.role,
        "department": user.department
    }
    access_token = create_access_token(token_data)

    # Set cookie for browser session
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=False,
        samesite="lax",
        max_age=3600 * 12
    )

    # Record successful login in immutable audit log
    record_audit_event(
        db=db,
        user_id=user.id,
        user_username=user.username,
        user_role=user.role,
        user_department=user.department,
        client_ip=client_ip,
        action="LOGIN",
        resource_type="auth_session",
        http_status=200,
        risk_score_assigned=0
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
            "department": user.department,
            "shift_start": user.shift_start,
            "shift_end": user.shift_end,
            "current_risk_score": user.current_risk_score,
            "is_quarantined": user.is_quarantined
        }
    }

@router.post("/logout")
async def logout(response: Response, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    response.delete_cookie("access_token")
    record_audit_event(
        db=db,
        user_id=current_user.id,
        user_username=current_user.username,
        user_role=current_user.role,
        user_department=current_user.department,
        action="LOGOUT",
        resource_type="auth_session",
        http_status=200
    )
    return {"message": "Logged out successfully."}

@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "department": current_user.department,
        "shift_start": current_user.shift_start,
        "shift_end": current_user.shift_end,
        "current_risk_score": current_user.current_risk_score,
        "is_quarantined": current_user.is_quarantined
    }

@router.get("/demo-users")
async def get_demo_users(db: Session = Depends(get_db)):
    """Returns quick switcher list of staff accounts for hackathon judges."""
    users = db.query(User).all()
    return [
        {
            "username": u.username,
            "email": u.email,
            "full_name": u.full_name,
            "role": u.role,
            "department": u.department,
            "shift": f"{u.shift_start} - {u.shift_end}",
            "is_quarantined": u.is_quarantined,
            "risk_score": u.current_risk_score
        }
        for u in users
    ]

