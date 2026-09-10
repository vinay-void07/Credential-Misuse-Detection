from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any

class UserRegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=6)
    role: Optional[str] = Field("intern", description="intern, senior_dev, admin")

class LoginRequest(BaseModel):
    username: str
    password: str
    client_device_id: Optional[str] = Field(None, description="Optional custom device identifier for demo simulation")
    demo_location: Optional[str] = Field("Chennai Office", description="Chennai Office, Coimbatore Office, or Remote")
    demo_device_type: Optional[str] = Field("known", description="known or new_device")

class TokenResponse(BaseModel):
    access_token: Optional[str] = None
    token_type: str = "bearer"
    user_id: Optional[int] = None
    username: Optional[str] = None
    role: Optional[str] = None
    session_id: Optional[int] = None
    session_token_id: Optional[str] = None
    device_fingerprint: Optional[str] = None
    risk_score: float = 0.0

    # Decision metadata included directly for portal client
    decision: str = "ALLOW"
    message: str = "Access granted"
    detected_reasons: List[str] = []
    verification_token: Optional[str] = None

class VerificationRequest(BaseModel):
    verification_token: str
    code: str = Field(..., description="Demo OTP verification code (e.g. 123456)")