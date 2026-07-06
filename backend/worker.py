import os
import asyncio
from celery import Celery
from config import settings
from store import ScanStore
from scanner.engine import run_scan

celery_app = Celery(
    "dast_worker",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

# We use a global store for the worker.
# In a real distributed system with multiple worker nodes, ScanStore would need to
# write to a shared database (like Postgres) instead of the local filesystem.
# For this Sentinel V1, we map the /data folder to a shared docker volume.
worker_store = ScanStore()

@celery_app.task(name="worker.run_scan_task")
def run_scan_task(scan_id: str):
    """
    Celery task that executes a scan in the background.
    Since run_scan is async and Celery tasks are sync by default, we wrap it in asyncio.run.
    """
    
    # Wait briefly to ensure the API has written the pending record to disk
    import time
    time.sleep(1)
    
    record = worker_store.get_record(scan_id)
    if not record:
        print(f"ERROR: Scan record {scan_id} not found in worker store.")
        return False
        
    try:
        # Run the async engine
        asyncio.run(run_scan(record, worker_store))
        return True
    except Exception as e:
        print(f"Task Failed: {e}")
        return False
