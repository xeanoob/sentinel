"""REST + SSE endpoints for scan management."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from starlette.responses import StreamingResponse

from config import settings
from models import ScanCreateResponse, ScanEvent, ScanRequest, ScanStatus
from scanner.engine import run_scan
from store import scan_store

router = APIRouter(prefix="/api/v1")


# ---------------------------------------------------------------------------
# POST /api/v1/scans — create & start a new scan
# ---------------------------------------------------------------------------

@router.post("/scans", response_model=ScanCreateResponse)
async def create_scan(request: ScanRequest) -> ScanCreateResponse:
    record = scan_store.create(request)

    try:
        from worker import run_scan_task
        run_scan_task.delay(record.scan_id)
    except Exception as e:
        # Fallback to local async if celery is not running (dev mode)
        print(f"Celery dispatch failed: {e}. Running locally.")
        task = asyncio.create_task(run_scan(record, scan_store))
        record.task = task

    return ScanCreateResponse(
        scan_id=record.scan_id,
        status=record.status,
    )


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id} — get scan summary
# ---------------------------------------------------------------------------

@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str):
    record = scan_store.get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return record.to_summary().model_dump()


# ---------------------------------------------------------------------------
# POST /api/v1/scans/{scan_id}/cancel — cancel a running scan
# ---------------------------------------------------------------------------

@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    record = scan_store.get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    if record.status not in (ScanStatus.RUNNING, ScanStatus.PENDING):
        raise HTTPException(status_code=409, detail="Scan is not running")

    # Signal cancellation
    record.cancel_event.set()

    # Wait a bit for the task to clean up
    if record.task and not record.task.done():
        record.task.cancel()
        try:
            await asyncio.wait_for(asyncio.shield(record.task), timeout=5.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

    return record.to_summary().model_dump()


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id}/stream — SSE event stream
# ---------------------------------------------------------------------------

@router.get("/scans/{scan_id}/stream")
async def scan_stream(scan_id: str):
    record = scan_store.get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    queue = scan_store.subscribe(scan_id)

    async def event_generator():
        """Yields SSE-formatted events."""
        try:
            while True:
                try:
                    # Wait for an event with a timeout for keepalive pings
                    event = await asyncio.wait_for(
                        queue.get(),
                        timeout=settings.SSE_PING_INTERVAL,
                    )
                except asyncio.TimeoutError:
                    # Send a ping to keep the connection alive
                    ping = ScanEvent(
                        scan_id=scan_id,
                        event="ping",
                        data={},
                    )
                    yield _format_sse(ping)
                    continue

                if event is None:
                    # Sentinel: stream is over
                    break

                yield _format_sse(event)

                # If this is a terminal event, stop streaming
                if event.event in ("scan_finished", "scan_cancelled", "scan_failed"):
                    break

        finally:
            scan_store.unsubscribe(scan_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _format_sse(event: ScanEvent) -> str:
    """Format a ScanEvent as an SSE message string.

    Format:
        event: <event_type>\n
        data: <json>\n
        \n
    """
    data_json = json.dumps(event.model_dump(), default=str)
    return f"event: {event.event}\ndata: {data_json}\n\n"


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id}/report — download HTML report
# ---------------------------------------------------------------------------

@router.get("/scans/{scan_id}/report")
async def download_report(scan_id: str):
    record = scan_store.get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    from fastapi.responses import HTMLResponse
    
    findings_html = ""
    for f in record.findings:
        color = "#dc2626" if f.severity.value == "Critical" else "#ea580c" if f.severity.value == "High" else "#ca8a04" if f.severity.value == "Medium" else "#2563eb"
        bg_color = "#fef2f2" if f.severity.value == "Critical" else "#fff7ed" if f.severity.value == "High" else "#fefce8" if f.severity.value == "Medium" else "#eff6ff"
        findings_html += f"""
        <div class="finding-card" style="border-left-color: {color};">
            <div class="finding-header" style="background-color: {bg_color}; border-bottom: 1px solid {color}33;">
                <span class="badge" style="background-color: {color}; color: white;">{f.severity.value.upper()}</span>
                <h3 style="margin: 0; font-size: 1.2em; color: #111827;">{f.vulnerability_type}</h3>
            </div>
            <div class="finding-body">
                <div class="field">
                    <div class="field-label">Target Resource</div>
                    <div class="field-value" style="font-family: monospace; font-size: 0.9em; background: #f3f4f6; padding: 4px 8px; border-radius: 4px; display: inline-block;">{f.url}</div>
                </div>
                <div class="field">
                    <div class="field-label">Description</div>
                    <div class="field-value">{f.description}</div>
                </div>
                <div class="field">
                    <div class="field-label">Remediation</div>
                    <div class="field-value">{f.recommendation}</div>
                </div>
            </div>
        </div>
        """

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Sentinel Security Report - {record.target_url}</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {{
                --border-color: #e5e7eb;
                --text-main: #1f2937;
                --text-muted: #6b7280;
            }}
            body {{ 
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; 
                background: #ffffff; 
                color: var(--text-main); 
                padding: 40px; 
                max-width: 1000px; 
                margin: auto; 
                line-height: 1.5;
            }}
            .header {{
                border-bottom: 2px solid #2563eb;
                padding-bottom: 20px;
                margin-bottom: 30px;
                display: flex;
                justify-content: space-between;
                align-items: flex-end;
            }}
            .header h1 {{
                margin: 0;
                color: #111827;
                font-size: 2.2em;
                letter-spacing: -0.02em;
            }}
            .header-meta {{
                text-align: right;
                font-size: 0.9em;
                color: var(--text-muted);
            }}
            .target-info {{
                background: #f8fafc;
                border: 1px solid var(--border-color);
                border-radius: 8px;
                padding: 20px;
                margin-bottom: 30px;
            }}
            .target-info p {{ margin: 5px 0; }}
            .summary {{ 
                display: grid; 
                grid-template-columns: repeat(5, 1fr); 
                gap: 15px; 
                margin-bottom: 40px; 
            }}
            .stat-box {{ 
                background: #ffffff; 
                padding: 20px 15px; 
                border: 1px solid var(--border-color); 
                border-radius: 8px; 
                text-align: center; 
                box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            }}
            .stat-value {{ 
                font-size: 2.2em; 
                font-weight: 700; 
                margin-bottom: 5px; 
                line-height: 1;
            }}
            .stat-label {{
                font-size: 0.85em;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                color: var(--text-muted);
                font-weight: 600;
            }}
            .Critical {{ color: #dc2626; }}
            .High {{ color: #ea580c; }}
            .Medium {{ color: #ca8a04; }}
            .Low {{ color: #2563eb; }}
            .Total {{ color: #111827; }}
            
            h2.section-title {{
                font-size: 1.5em;
                color: #111827;
                border-bottom: 1px solid var(--border-color);
                padding-bottom: 10px;
                margin-top: 40px;
                margin-bottom: 20px;
            }}

            .finding-card {{
                border: 1px solid var(--border-color);
                border-left-width: 4px;
                border-radius: 8px;
                margin-bottom: 25px;
                overflow: hidden;
                page-break-inside: avoid;
                box-shadow: 0 1px 2px rgba(0,0,0,0.05);
            }}
            .finding-header {{
                padding: 15px 20px;
                display: flex;
                align-items: center;
                gap: 15px;
            }}
            .badge {{
                padding: 4px 10px;
                border-radius: 9999px;
                font-size: 0.75em;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }}
            .finding-body {{
                padding: 20px;
                background: #ffffff;
            }}
            .field {{ margin-bottom: 15px; }}
            .field:last-child {{ margin-bottom: 0; }}
            .field-label {{
                font-size: 0.85em;
                font-weight: 600;
                color: var(--text-muted);
                text-transform: uppercase;
                letter-spacing: 0.05em;
                margin-bottom: 5px;
            }}
            .field-value {{
                color: var(--text-main);
                white-space: pre-wrap;
            }}
            
            footer {{
                margin-top: 60px;
                padding-top: 20px;
                border-top: 1px solid var(--border-color);
                text-align: center;
                color: var(--text-muted);
                font-size: 0.85em;
            }}
            
            @media print {{
                body {{ padding: 0; }}
                .finding-card {{ box-shadow: none; }}
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <h1>Sentinel Security Audit</h1>
                <div style="color: #2563eb; font-weight: 600; margin-top: 5px;">Automated DAST Report</div>
            </div>
            <div class="header-meta">
                <div>{record.started_at.strftime('%B %d, %Y') if record.started_at else 'N/A'}</div>
                <div>Status: <strong>{record.status.value.upper()}</strong></div>
            </div>
        </div>
        
        <div class="target-info">
            <p><strong>Target URL:</strong> <a href="{record.target_url}" style="color: #2563eb; text-decoration: none;">{record.target_url}</a></p>
            <p><strong>Scan Duration:</strong> {((record.finished_at - record.started_at).total_seconds()) if record.finished_at and record.started_at else 0} seconds</p>
            <p><strong>Scan ID:</strong> <span style="font-family: monospace;">{record.scan_id}</span></p>
        </div>
        
        <div class="summary">
            <div class="stat-box">
                <div class="stat-value Total">{record.pages_visited}</div>
                <div class="stat-label">Pages</div>
            </div>
            <div class="stat-box">
                <div class="stat-value Critical">{record.severity_counts.get("Critical", 0)}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-box">
                <div class="stat-value High">{record.severity_counts.get("High", 0)}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-box">
                <div class="stat-value Medium">{record.severity_counts.get("Medium", 0)}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-box">
                <div class="stat-value Low">{record.severity_counts.get("Low", 0)}</div>
                <div class="stat-label">Low</div>
            </div>
        </div>

        <h2 class="section-title">Detailed Findings</h2>
        {findings_html if record.findings else '<div style="text-align: center; padding: 40px; background: #f0fdf4; color: #166534; border-radius: 8px; border: 1px solid #bbf7d0;">🎉 <strong>Excellent!</strong> No vulnerabilities were detected during this scan.</div>'}
        
        <footer>
            Generated by Sentinel DAST. Printed on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}.<br/>
            This is an automated security report. Please verify findings manually.
        </footer>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html)


# ---------------------------------------------------------------------------
# GET /api/v1/scans/{scan_id}/pdf — download Native PDF report
# ---------------------------------------------------------------------------

@router.get("/scans/{scan_id}/pdf")
async def download_pdf_report(scan_id: str):
    from fastapi.responses import Response
    from playwright.async_api import async_playwright
    import os
    
    # We will simply ask Playwright to render our HTML report
    # and print it to PDF!
    report_url = f"http://127.0.0.1:{settings.PORT}/api/v1/scans/{scan_id}/report"
    
    try:
        async with async_playwright() as p:
            # We use chromium for best PDF generation support
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto(report_url, wait_until="networkidle")
            
            # Print to PDF buffer
            pdf_bytes = await page.pdf(
                format="A4",
                print_background=True,
                margin={"top": "10mm", "bottom": "10mm", "left": "10mm", "right": "10mm"}
            )
            
            await browser.close()
            
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="sentinel_report_{scan_id}.pdf"'}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {e}")

# ---------------------------------------------------------------------------
# GET /api/v1/scans — get scan history
# ---------------------------------------------------------------------------

@router.get("/scans")
async def get_scans_history():
    return scan_store.load_history()


# ---------------------------------------------------------------------------
# GET /api/v1/scans/compare — compare two scans
# ---------------------------------------------------------------------------

@router.get("/scans/compare")
async def compare_scans(base_id: str, new_id: str):
    base_scan = scan_store.get(base_id)
    new_scan = scan_store.get(new_id)
    
    # Try loading from disk if not in memory
    if not base_scan or not new_scan:
        history = scan_store.load_history()
        base_data = next((s for s in history if s["scan_id"] == base_id), None)
        new_data = next((s for s in history if s["scan_id"] == new_id), None)
        
        if not base_data or not new_data:
            raise HTTPException(status_code=404, detail="One or both scans not found")
            
        base_findings = base_data.get("findings", [])
        new_findings = new_data.get("findings", [])
    else:
        base_findings = [f.model_dump() for f in base_scan.findings]
        new_findings = [f.model_dump() for f in new_scan.findings]

    # Simple comparison based on URL and Vulnerability Type
    def finding_key(f): return f"{f['url']}|{f['vulnerability_type']}"
    
    base_keys = {finding_key(f): f for f in base_findings}
    new_keys = {finding_key(f): f for f in new_findings}
    
    resolved = [f for key, f in base_keys.items() if key not in new_keys]
    introduced = [f for key, f in new_keys.items() if key not in base_keys]
    persisted = [f for key, f in new_keys.items() if key in base_keys]
    
    return {
        "base_scan_id": base_id,
        "new_scan_id": new_id,
        "resolved_count": len(resolved),
        "introduced_count": len(introduced),
        "persisted_count": len(persisted),
        "resolved": resolved,
        "introduced": introduced,
        "persisted": persisted
    }


# ---------------------------------------------------------------------------
# POST /api/v1/false-positives — Register a false positive
# ---------------------------------------------------------------------------

from pydantic import BaseModel

class FalsePositiveRequest(BaseModel):
    url: str
    vulnerability_type: str

@router.post("/false-positives")
async def register_false_positive(request: FalsePositiveRequest):
    from false_positives import fp_manager
    fp_manager.register(request.url, request.vulnerability_type)
    return {"status": "ok", "message": "False positive registered successfully"}
