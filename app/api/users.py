from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.database.database import get_db
from app.database.models import User
from app.schemas.users import UserResponse
from app.core.dependencies import get_current_user_and_session, require_admin

router = APIRouter(prefix="/users", tags=["Users"])

@router.get("", response_model=List[UserResponse])
def list_users(
    auth_data = Depends(get_current_user_and_session),
    db: Session = Depends(get_db)
):
    """List system users. Restricted to Admin role."""
    current_user, _ = auth_data
    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return db.query(User).all()

@router.get("/{user_id}", response_model=UserResponse)
def get_user(
    user_id: int,
    auth_data = Depends(get_current_user_and_session),
    db: Session = Depends(get_db)
):
    """Get user by ID. Users can inspect themselves; Admins can inspect anyone."""
    current_user, _ = auth_data
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user
