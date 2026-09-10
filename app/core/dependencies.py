from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional

from app.database.database import get_db
from app.database.models import User, Session as UserSession
from app.core.security import decode_access_token

security_scheme = HTTPBearer(auto_error=False)

def get_current_user_and_session(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: Session = Depends(get_db)
):
    """
    Authenticate request via JWT and verify active session in SQLite DB.
    Attaches user and session to request.state for activity logger middleware.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid authentication token"
        )
    
    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token"
        )

    user_id = payload.get("user_id")
    session_id = payload.get("session_id")
    session_token_id = payload.get("session_token_id")

    if not user_id or not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed token payload"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )

    user_session = db.query(UserSession).filter(
        UserSession.id == session_id,
        UserSession.user_id == user.id
    ).first()

    if not user_session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session not found"
        )

    # Validate that session has not been terminated or expired
    if user_session.status == "terminated":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been terminated. Please re-authenticate."
        )

    if user_session.status == "expired":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired"
        )

    # Attach to request state for downstream logging and detection
    request.state.current_user = user
    request.state.current_session = user_session

    return user, user_session

def get_current_user(auth_data = Depends(get_current_user_and_session)) -> User:
    user, _ = auth_data
    return user

def get_current_session(auth_data = Depends(get_current_user_and_session)) -> UserSession:
    _, session = auth_data
    return session

def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privilege required"
        )
    return current_user

def require_senior_or_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role not in ("admin", "senior_dev"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Senior developer or Admin privilege required"
        )
    return current_user
