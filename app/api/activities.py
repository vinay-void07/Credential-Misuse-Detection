from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.database.database import get_db
from app.database.models import ActivityLog, User
from app.schemas.activity import ActivityLogResponse
from app.core.dependencies import get_current_user_and_session

router = APIRouter(prefix="/activities", tags=["Activity Logs"])

@router.get("", response_model=List[ActivityLogResponse])
def list_activities(
    user_id: Optional[int] = None,
    session_id: Optional[int] = None,
    limit: int = 100,
    auth_data = Depends(get_current_user_and_session),
    db: Session = Depends(get_db)
):
    current_user, _ = auth_data
    query = db.query(ActivityLog)
    if current_user.role != 'admin':
        query = query.filter(ActivityLog.user_id == current_user.id)
    elif user_id:
        query = query.filter(ActivityLog.user_id == user_id)

    if session_id:
        query = query.filter(ActivityLog.session_id == session_id)

    return query.order_by(ActivityLog.timestamp.desc()).limit(limit).all()
