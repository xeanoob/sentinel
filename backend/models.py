"""Pydantic models and internal data structures for the DAST scanner."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# API request / response models (match the frontend contract)
# ---------------------------------------------------------------------------

class AuthConfig(BaseModel):
    login_url: str
    username_selector: str
    password_selector: str
    submit_selector: str
    username: str
    password: str


class ScanRequest(BaseModel):
    target_url: str
    max_depth: int = 3
    max_concurrency: int = 10
    page_timeout_ms: int = 15000
    same_domain_only: bool = True
    use_browser: bool = False
    custom_headers: dict[str, str] = Field(default_factory=dict)
    stealth_mode: bool = False
    auth_config: Optional[AuthConfig] = None
    is_api_scan: bool = False
    active_fuzzing: bool = False
    is_graphql_scan: bool = False
    ai_api_key: Optional[str] = None
    secondary_auth_config: Optional[AuthConfig] = None
    webhook_url: Optional[str] = None


class ScanCreateResponse(BaseModel):
    scan_id: str
    status: ScanStatus


class ScanSummary(BaseModel):
    scan_id: str
    status: ScanStatus
    target_url: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    pages_visited: int = 0
    findings_count: int = 0
    severity_counts: dict[str, int] = Field(
        default_factory=lambda: {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    )
    result: Any = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Finding (matches the frontend Finding type)
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    url: str
    vulnerability_type: str
    severity: Severity
    description: str
    recommendation: str


# ---------------------------------------------------------------------------
# Crawled page data
# ---------------------------------------------------------------------------

class FormField(BaseModel):
    name: str
    field_type: str = "text"
    value: str = ""


class FormData(BaseModel):
    action: str
    method: str = "GET"
    fields: list[FormField] = Field(default_factory=list)


class CrawledPage(BaseModel):
    """All data collected for a single visited page."""
    url: str
    depth: int = 0
    status_code: int = 0
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    content_type: str = ""
    forms: list[FormData] = Field(default_factory=list)
    links: list[str] = Field(default_factory=list)
    url_params: dict[str, list[str]] = Field(default_factory=dict)
    set_cookie_headers: list[str] = Field(default_factory=list)
    is_active_fuzzing: bool = False
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# SSE event
# ---------------------------------------------------------------------------

class ScanEvent(BaseModel):
    scan_id: str
    event: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    data: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Internal scan record (not exposed via API)
# ---------------------------------------------------------------------------

class ScanRecord:
    """Mutable internal state for a running scan."""

    def __init__(self, scan_id: str, request: ScanRequest) -> None:
        self.scan_id = scan_id
        self.request = request
        self.status = ScanStatus.PENDING
        self.target_url = request.target_url
        self.started_at: Optional[datetime] = None
        self.finished_at: Optional[datetime] = None
        self.pages_visited: int = 0
        self.findings: list[Finding] = []
        self.severity_counts: dict[str, int] = {
            "Critical": 0, "High": 0, "Medium": 0, "Low": 0,
        }
        self.error: Optional[str] = None
        self.cancel_event: asyncio.Event = asyncio.Event()
        self.task: Optional[asyncio.Task[None]] = None

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.severity_counts[finding.severity.value] += 1

    def to_summary(self) -> ScanSummary:
        return ScanSummary(
            scan_id=self.scan_id,
            status=self.status,
            target_url=self.target_url,
            started_at=self.started_at.isoformat() if self.started_at else None,
            finished_at=self.finished_at.isoformat() if self.finished_at else None,
            pages_visited=self.pages_visited,
            findings_count=len(self.findings),
            severity_counts=self.severity_counts,
            error=self.error,
        )
