import json
import os
import uuid
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from models import ScanRequest

router = APIRouter(prefix="/api/v1")
SCHEDULE_FILE = "data/scans/schedules.json"

class ScheduleCreate(BaseModel):
    name: str
    cron_expression: str
    config: ScanRequest
    enabled: bool = True

from typing import List, Dict, Any, Optional

class ScheduleResponse(ScheduleCreate):
    id: str
    last_run: Optional[str] = None

def load_schedules() -> List[Dict[Any, Any]]:
    if not os.path.exists(SCHEDULE_FILE):
        return []
    try:
        with open(SCHEDULE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []

def save_schedules(schedules: List[Dict[Any, Any]]):
    with open(SCHEDULE_FILE, "w") as f:
        json.dump(schedules, f, indent=2)

@router.get("/schedules", response_model=List[ScheduleResponse])
async def get_schedules():
    return load_schedules()

@router.post("/schedules", response_model=ScheduleResponse)
async def create_schedule(schedule: ScheduleCreate):
    schedules = load_schedules()
    new_schedule = schedule.model_dump()
    new_schedule["id"] = str(uuid.uuid4())
    new_schedule["last_run"] = None
    schedules.append(new_schedule)
    save_schedules(schedules)
    return new_schedule

@router.delete("/schedules/{schedule_id}")
async def delete_schedule(schedule_id: str):
    schedules = load_schedules()
    new_schedules = [s for s in schedules if s["id"] != schedule_id]
    if len(schedules) == len(new_schedules):
        raise HTTPException(status_code=404, detail="Schedule not found")
    save_schedules(new_schedules)
    return {"success": True}
