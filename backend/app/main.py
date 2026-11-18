import os
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from app.api.auth import router as auth_router
from app.api.patients import router as patients_router
from app.api.records import router as records_router
from app.api.audit import router as audit_router
from app.api.soc import router as soc_router
from app.api.simulator import router as simulator_router
from app.services.websocket_manager import ws_hub

APP_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = APP_DIR.parent.parent
STATIC_DIR = PROJECT_ROOT / "frontend" / "static"
TEMPLATES_DIR = PROJECT_ROOT / "frontend" / "templates"

STATIC_DIR.mkdir(parents=True, exist_ok=True)
TEMPLATES_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="AegisHealth EHR & Cyber-SOC Monitoring Platform",
    description="HIPAA/GDPR-compliant EHR system with RBAC/ABAC and Real-Time UEBA Threat Detection Engine.",
    version="1.0.0"
)

# Enable CORS for local and demo origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def security_compliance_middleware(request: Request, call_next):
    """
    Enforces HIPAA Security Rule §164.312(e)(1), NIST SP 800-53 (SC-8, SC-13, SC-28),
    and OWASP Top 10 defensive HTTP security headers across all transactions.
    """
    response = await call_next(request)
    
    # 1. Clickjacking Protection (NIST AC-4, OWASP A05)
    response.headers["X-Frame-Options"] = "DENY"
    
    # 2. MIME-type Sniffing Prevention (OWASP A05)
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    # 3. Cross-Site Scripting Protection (Legacy browser fallback)
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # 4. Strict Transport Security (HSTS - HIPAA §164.312(e)(1), NIST SC-8)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    
    # 5. Referrer Policy (HIPAA Minimum Necessary PHI protection in URLs)
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # 6. Permissions / Feature Policy (Restricting hardware access)
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    
    # 7. Content Security Policy (CSP - OWASP A03 / A05)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://unpkg.com https://cdn.jsdelivr.net data: ws: wss:; "
        "frame-ancestors 'none';"
    )
    
    # 8. ePHI Cache-Control (HIPAA §164.312(a)(1) & NIST AC-11)
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    
    # 9. Standards Compliance Declaration Header
    response.headers["X-Compliance-Frameworks"] = "HIPAA-45CFR164, NIST-SP-800-53-Rev5, HITRUST-CSF-v11, GDPR-Art32, OWASP-Top10"
    
    return response

# Mount Routers
app.include_router(auth_router)
app.include_router(patients_router)
app.include_router(records_router)
app.include_router(audit_router)
app.include_router(soc_router)
app.include_router(simulator_router)

# Mount Static Files and Templates
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

@app.websocket("/ws/soc")
async def websocket_soc_endpoint(websocket: WebSocket):
    """Real-time streaming socket for SOC alerts and cryptographic audit events."""
    await ws_hub.connect(websocket)
    try:
        while True:
            # Keep-alive receive loop
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_hub.disconnect(websocket)
    except Exception:
        ws_hub.disconnect(websocket)

@app.get("/", response_class=HTMLResponse)
async def serve_index(request: Request):
    """Serves the primary AegisHealth unified frontend shell."""
    return templates.TemplateResponse(request=request, name="index.html")

@app.get("/health")
async def health_check():
    return {"status": "HEALTHY", "system": "AegisHealth Healthcare Data Security Platform", "version": "1.0.0"}

