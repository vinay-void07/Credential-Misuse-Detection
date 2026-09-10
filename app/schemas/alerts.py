from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Any, Dict

class AlertResponse(BaseModel):
    id: int
    user_id: int
    session_id: int
    severity: str
    risk_score: float
    alert_type: str
    title: str
    description: str
    evidence: Dict[str, Any]
    recommended_action: str
    created_at: datetime
    status: str

    class Config:
        from_attributes = True

class AlertStatusUpdate(BaseModel):
    status: str = Field(..., description="open, investigating, resolved")

class SessionResponse(BaseModel):
    id: int
    user_id: int
    session_token_id: str
    ip_address: Optional[str]
    device_fingerprint: str
    started_at: datetime
    last_activity_at: datetime
    risk_score: float
    status: str

    class Config:
        from_attributes = True
