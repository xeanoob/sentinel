from celery import Celery
from celery.schedules import crontab
from worker import celery_app
import json
import os
from models import ScanRequest
from store import scan_store
from routes.scans import create_scan

SCHEDULE_FILE = "data/scans/schedules.json"

@celery_app.task(name="scheduler.run_scheduled_scan")
def run_scheduled_scan(schedule_id: str):
    """Executes a scheduled scan."""
    try:
        if not os.path.exists(SCHEDULE_FILE):
            return False
            
        with open(SCHEDULE_FILE, "r") as f:
            schedules = json.load(f)
            
        schedule = next((s for s in schedules if s["id"] == schedule_id), None)
        if not schedule:
            return False
            
        # Create a new scan based on the schedule's config
        request = ScanRequest(**schedule["config"])
        
        # We need to dispatch the task just like the API does
        from worker import run_scan_task
        record = scan_store.create(request)
        run_scan_task.delay(record.scan_id)
        
        # Update last run time
        from datetime import datetime, timezone
        schedule["last_run"] = datetime.now(timezone.utc).isoformat()
        
        with open(SCHEDULE_FILE, "w") as f:
            json.dump(schedules, f, indent=2)
            
        return True
    except Exception as e:
        print(f"Failed to run scheduled scan: {e}")
        return False

# In a real app we would dynamically update Celery Beat schedule
# For this version, we will have a fast periodic task that checks the schedules.json manually
@celery_app.task(name="scheduler.check_schedules")
def check_schedules():
    import croniter
    from datetime import datetime, timezone
    
    if not os.path.exists(SCHEDULE_FILE):
        return
        
    try:
        with open(SCHEDULE_FILE, "r") as f:
            schedules = json.load(f)
            
        now = datetime.now(timezone.utc)
        
        for schedule in schedules:
            if not schedule.get("enabled", True):
                continue
                
            # Use croniter to check if we should run
            cron = croniter.croniter(schedule["cron_expression"], now)
            prev_run = cron.get_prev(datetime)
            
            # If the last time the cron was supposed to run is AFTER our last recorded run
            # It means we missed it and should run it now.
            last_recorded_run_str = schedule.get("last_run")
            if not last_recorded_run_str:
                # Never run before, run it now
                run_scheduled_scan.delay(schedule["id"])
                continue
                
            last_recorded_run = datetime.fromisoformat(last_recorded_run_str)
            
            # Convert prev_run to aware datetime
            prev_run = prev_run.replace(tzinfo=timezone.utc)
            
            if prev_run > last_recorded_run:
                run_scheduled_scan.delay(schedule["id"])
                
    except Exception as e:
        print(f"Error checking schedules: {e}")

# Run the checker every minute
celery_app.conf.beat_schedule = {
    'check-schedules-every-minute': {
        'task': 'scheduler.check_schedules',
        'schedule': crontab(minute='*'),
    },
}
