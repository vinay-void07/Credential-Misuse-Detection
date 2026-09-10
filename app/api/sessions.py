from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.database.database import get_db
from app.database.models import Session as UserSession, User
from app.schemas.alerts import SessionResponse
from app.core.dependencies import get_current_user_and_session, require_admin

router = APIRouter(prefix="/sessions", tags=["Sessions"])

@router.get("", response_model=List[SessionResponse])
def list_sessions(
    user_id: Optional[int] = None,
    status_filter: Optional[str] = None,
    auth_data = Depends(get_current_user_and_session),
    db: Session = Depends(get_db)
):
    """
    List user sessions. Non-admins can only see their own active sessions.
    Admins can view all system sessions.
    """
    current_user, _ = auth_data
    query = db.query(UserSession)
    
    if current_user.role != "admin":
        query = query.filter(UserSession.user_id == current_user.id)
    elif user_id is not None:
        query = query.filter(UserSession.user_id == user_id)

    if status_filter:
        query = query.filter(UserSession.status == status_filter.lower())

    return query.order_by(UserSession.started_at.desc()).all()

@router.get("/{session_id}", response_model=SessionResponse)
def get_session(
    session_id: int,
    auth_data = Depends(get_current_user_and_session),
    db: Session = Depends(get_db)
):
    """Retrieve session metadata, device fingerprint, and current risk score."""
    current_user, _ = auth_data
    user_session = db.query(UserSession).filter(UserSession.id == session_id).first()
    if not user_session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    if current_user.role != "admin" and user_session.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    return user_session

@router.post("/{session_id}/terminate", response_model=SessionResponse)
def terminate_session(
    session_id: int,
    auth_data = Depends(get_current_user_and_session),
    db: Session = Depends(get_db)
):
    """
    Terminate an active session server-side.
    Any further requests with the associated JWT will be immediately rejected with 401 Unauthorized.
    """
    current_user, _ = auth_data
    user_session = db.query(UserSession).filter(UserSession.id == session_id).first()
    if not user_session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    # Users can terminate their own session; Admins can terminate any session
    if current_user.role != "admin" and user_session.user_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    user_session.status = "terminated"
    db.commit()
    db.refresh(user_session)
    return user_session
