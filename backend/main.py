"""Sentinel — Security Scanner Backend.

Usage:
    python main.py
    # or
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import logging
import sys
import warnings

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings
from routes.scans import router as scans_router
from routes.schedules import router as schedules_router
from routes.analytics import router as analytics_router

# Suppress SSL warnings (we intentionally scan with verify=False)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("dast")

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Sentinel API",
    version="1.0.0",
    description=(
        "Sentinel — Moteur de scan de sécurité web. "
        "Crawle les sites cibles et détecte les vulnérabilités en temps réel."
    ),
)

# CORS — allow the Next.js frontend on any port
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(scans_router)


# ---------------------------------------------------------------------------
# Root endpoint (health check)
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    return {
        "service": "Sentinel API",
        "version": "1.0.0",
        "status": "operational",
    }


# ---------------------------------------------------------------------------
# Startup banner
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup_banner():
    logger.info("=" * 60)
    logger.info("  ⬡  SENTINEL v1.0.0")
    logger.info("  Listening on http://%s:%d", settings.HOST, settings.PORT)
    logger.info("")
    logger.info("  ⚠️  USAGE ÉTHIQUE UNIQUEMENT")
    logger.info("  Scannez uniquement vos propres sites ou ceux")
    logger.info("  pour lesquels vous avez une autorisation écrite.")
    logger.info("=" * 60)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True,
        log_level="info",
    )
