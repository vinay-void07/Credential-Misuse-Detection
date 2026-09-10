from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Any, Dict

class ActivityLogResponse(BaseModel):
    id: int
    user_id: Optional[int]
    session_id: Optional[int]
    timestamp: datetime
    endpoint: str
    action: str
    resource_id: Optional[int]
    resource_sensitivity: Optional[str]
    ip_address: Optional[str]
    device_fingerprint: Optional[str]
    allowed: bool
    status_code: int
    response_time: float
    request_metadata: Optional[Dict[str, Any]]

    class Config:
        from_attributes = True
