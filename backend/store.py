"""In-memory scan store with pub/sub for SSE streaming."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional, Union
from uuid import uuid4

from models import ScanEvent, ScanRecord, ScanRequest


class ScanStore:
    """Thread-safe (asyncio) in-memory store for scans and SSE subscribers."""

    def __init__(self) -> None:
        self._scans: dict[str, ScanRecord] = {}
        self._subscribers: dict[str, list[asyncio.Queue]] = {}
        self.save_dir = Path("data/scans")
        self.save_dir.mkdir(parents=True, exist_ok=True)

    def create(self, request: ScanRequest) -> ScanRecord:
        scan_id = uuid4().hex[:12]
        record = ScanRecord(scan_id, request)
        self._scans[scan_id] = record
        self._subscribers[scan_id] = []
        return record

    def get(self, scan_id: str) -> Optional[ScanRecord]:
        return self._scans.get(scan_id)

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        """Create a new subscriber queue for SSE streaming.
        Returns a Queue that receives ScanEvent objects.
        A None sentinel signals end-of-stream."""
        queue: asyncio.Queue = asyncio.Queue()
        if scan_id not in self._subscribers:
            self._subscribers[scan_id] = []
        self._subscribers[scan_id].append(queue)
        return queue

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        subs = self._subscribers.get(scan_id)
        if subs:
            try:
                subs.remove(queue)
            except ValueError:
                pass

    async def publish(self, scan_id: str, event: ScanEvent) -> None:
        """Broadcast an event to all subscribers of a given scan."""
        for queue in self._subscribers.get(scan_id, []):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass  # drop if subscriber is too slow

    async def close_subscribers(self, scan_id: str) -> None:
        """Send None sentinel to all subscribers to signal end-of-stream."""
        for queue in self._subscribers.get(scan_id, []):
            try:
                queue.put_nowait(None)
            except asyncio.QueueFull:
                pass


    def save_to_disk(self, scan_id: str) -> None:
        """Save a completed scan to disk."""
        record = self.get(scan_id)
        if not record: return
        
        try:
            # We don't save the asyncio primitives, only the data
            data = {
                "scan_id": record.scan_id,
                "request": record.request.model_dump(),
                "status": record.status,
                "pages_visited": record.pages_visited,
                "findings": [f.model_dump() for f in record.findings],
                "error": record.error,
                "start_time": record.started_at.isoformat() if getattr(record, "started_at", None) else None,
                "end_time": record.finished_at.isoformat() if getattr(record, "finished_at", None) else None,
            }
            
            with open(self.save_dir / f"{scan_id}.json", "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Failed to save scan to disk: {e}")

    def load_history(self) -> list[dict]:
        """Load all historical scans from disk."""
        history = []
        for file in self.save_dir.glob("*.json"):
            try:
                with open(file, "r") as f:
                    history.append(json.load(f))
            except Exception:
                continue
        # Sort by start_time descending
        return sorted(history, key=lambda x: x.get("start_time", ""), reverse=True)


# Singleton instance
scan_store = ScanStore()
