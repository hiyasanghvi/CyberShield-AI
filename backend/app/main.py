import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from app.api.routes.apk_analysis import (
    router as apk_analysis_router
)
from app.api.routes.safety_assistant import (
    router as safety_assistant_router
)
from app.db.database import (
    test_db_connection,
    create_tables,
)
from app.api.routes.screenshot_analysis import (
    router as screenshot_analysis_router
)

from app.api.routes.auth import (
    router as auth_router
)
from app.api.routes.network_security import (
    router as network_security_router
)
from app.api.routes.correlation import (
    router as correlation_router
)
from app.api.routes.url_analysis import router as url_analysis_router
from app.api.routes.dashboard import router as dashboard_router
from app.api.routes.qr_security import router as qr_security_router

from app.api.routes.sms_analysis import router as sms_analysis_router
from app.api.routes.email_analysis import router as email_analysis_router
from app.api.routes.unified_history import router as unified_history_router
from app.api.routes.threat_intelligence import (
    router as threat_intelligence_router
)
from app.api.routes.privacy import router as privacy_router
app = FastAPI(
    title="CyberShield-AI API",
    version="0.1.0",
)

if os.getenv("ENFORCE_HTTPS", "false").lower() == "true":
    app.add_middleware(HTTPSRedirectMiddleware)

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173",
        ).split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================================================
# CREATE DATABASE TABLES
# ==================================================

create_tables()


# ==================================================
# ROUTES
# ==================================================

app.include_router(
    auth_router
)
app.include_router(qr_security_router)
app.include_router(url_analysis_router)
app.include_router(dashboard_router)
app.include_router(sms_analysis_router)
app.include_router(email_analysis_router)
app.include_router(unified_history_router)
app.include_router(threat_intelligence_router)
app.include_router(correlation_router)
app.include_router(network_security_router)
app.include_router(apk_analysis_router)
app.include_router(screenshot_analysis_router)
app.include_router(safety_assistant_router)
app.include_router(privacy_router)
# ==================================================
# HEALTH CHECK
# ==================================================

@app.get("/api/health")
def health():

    return {
        "status": "ok",
        "project": "CyberShield-AI",
    }


# ==================================================
# DATABASE HEALTH CHECK
# ==================================================

@app.get("/api/health/db")
def database_health():

    result = test_db_connection()

    return {
        "status": "ok",
        "database": "connected",
        "test": result,
    }
