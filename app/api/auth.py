from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
import uuid
from datetime import datetime, timezone

from app.database.database import get_db
from app.database.models import User, Session as UserSession
from app.schemas.auth import (
    UserRegisterRequest, LoginRequest, TokenResponse, VerificationRequest
)
from app.schemas.users import UserResponse
from app.core.security import hash_password, verify_password, create_access_token, generate_device_fingerprint
from app.core.dependencies import get_current_user
from app.core.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])

PENDING_VERIFICATIONS = {}

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(req: UserRegisterRequest, db: Session = Depends(get_db)):
    """Register a new user account with hashed credentials."""
    existing = db.query(User).filter((User.username == req.username) | (User.email == req.email)).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )
    
    role = req.role if req.role in ("intern", "senior_dev", "admin") else "intern"
    new_user = User(
        username=req.username,
        email=req.email,
        password_hash=hash_password(req.password),
        role=role,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@router.post("/login", response_model=TokenResponse)
def login(login_data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """
    Authenticate user credentials, evaluate behavioral & context signals,
    and return structured login decision: ALLOW, VERIFICATION_REQUIRED, or CRITICAL.
    """
    user = db.query(User).filter(User.username == login_data.username).first()
    if not user or not verify_password(login_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive"
        )

    device_id = login_data.client_device_id
    if login_data.demo_device_type == "new_device":
        device_id = f"new-device-{uuid.uuid4().hex[:8]}"
    elif not device_id:
        device_id = request.headers.get("x-device-id", "office-workstation-01")

    user_agent = request.headers.get("user-agent", "Mozilla/5.0")
    client_ip = request.client.host if request.client else "127.0.0.1"
    device_fingerprint = generate_device_fingerprint(
        user_agent=user_agent,
        client_device_id=device_id,
        ip_address=client_ip
    )

    is_new_device = (login_data.demo_device_type == "new_device")
    location = login_data.demo_location or "Chennai Office"
    is_unusual_location = (location == "Remote")

    # Only evaluate off-hours if simulated explicitly via header or if simulated time
    is_explicit_off_hours = False
    simulated_hour = request.headers.get("x-simulated-hour")
    if simulated_hour:
        try:
            h = int(simulated_hour)
            is_explicit_off_hours = (h < settings.WORK_HOUR_START or h >= settings.WORK_HOUR_END)
        except Exception:
            pass

    detected_reasons = []
    if is_new_device:
        detected_reasons.append("Unrecognized / New Device Fingerprint detected")
    if is_unusual_location:
        detected_reasons.append(f"Unusual Access Location flagged ({location})")
    if is_explicit_off_hours:
        detected_reasons.append("Sign-in outside authorized working hours (23:00 Off-Hours)")

    # Establish session
    session_token_id = str(uuid.uuid4())
    user_session = UserSession(
        user_id=user.id,
        session_token_id=session_token_id,
        ip_address=client_ip,
        device_fingerprint=device_fingerprint,
        risk_score=0.0,
        status="active"
    )
    db.add(user_session)
    db.commit()
    db.refresh(user_session)

    # Attach to request state for activity logger
    request.state.current_user = user
    request.state.current_session = user_session

    # Prepare signed JWT
    token_payload = {
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "session_id": user_session.id,
        "session_token_id": session_token_id
    }
    access_token = create_access_token(token_payload)

    # Outcome 3: CRITICAL (If explicit off-hours combined with remote and new device)
    if is_explicit_off_hours and is_new_device and is_unusual_location:
        user_session.status = "terminated"
        user_session.risk_score = 92.0
        db.commit()
        return TokenResponse(
            decision="CRITICAL",
            message="Prism Network detected highly abnormal activity associated with this login attempt.",
            detected_reasons=detected_reasons,
            risk_score=92.0,
            session_id=user_session.id
        )

    # Outcome 2: VERIFICATION_REQUIRED (If demo controls request new device or remote access)
    if is_new_device or is_unusual_location:
        v_token = str(uuid.uuid4())
        PENDING_VERIFICATIONS[v_token] = {
            "access_token": access_token,
            "user_id": user.id,
            "username": user.username,
            "role": user.role,
            "session_id": user_session.id,
            "session_token_id": session_token_id,
            "device_fingerprint": device_fingerprint,
            "risk_score": 55.0
        }
        return TokenResponse(
            decision="VERIFICATION_REQUIRED",
            message="We detected unusual sign-in activity. Please complete the additional security check to continue.",
            detected_reasons=detected_reasons,
            verification_token=v_token,
            risk_score=55.0,
            session_id=user_session.id
        )

    # Outcome 1: ALLOW (Standard normal login)
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user_id=user.id,
        username=user.username,
        role=user.role,
        session_id=user_session.id,
        session_token_id=session_token_id,
        device_fingerprint=device_fingerprint,
        risk_score=user_session.risk_score,
        decision="ALLOW",
        message="Your identity and access context have been verified.",
        detected_reasons=[]
    )

@router.post("/verify", response_model=TokenResponse)
def verify_login_code(req: VerificationRequest, db: Session = Depends(get_db)):
    """
    Validate the demo verification code (123456) against the pending verification session.
    Returns the final TokenResponse with access_token.
    """
    v_data = PENDING_VERIFICATIONS.get(req.verification_token)
    if not v_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification session"
        )

    if req.code.strip() != "123456":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code. Please enter the demo code: 123456"
        )

    PENDING_VERIFICATIONS.pop(req.verification_token, None)
    
    return TokenResponse(
        access_token=v_data["access_token"],
        token_type="bearer",
        user_id=v_data["user_id"],
        username=v_data["username"],
        role=v_data["role"],
        session_id=v_data["session_id"],
        session_token_id=v_data["session_token_id"],
        device_fingerprint=v_data["device_fingerprint"],
        risk_score=v_data["risk_score"],
        decision="ALLOW",
        message="Additional security verification successful. Access granted.",
        detected_reasons=[]
    )

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    """Retrieve the profile of the currently authenticated user."""
    return current_user