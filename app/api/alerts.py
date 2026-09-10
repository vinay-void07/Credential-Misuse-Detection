from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional

from app.database.database import get_db
from app.database.models import Alert, User
from app.schemas.alerts import AlertResponse, AlertStatusUpdate
from app.core.dependencies import get_current_user_and_session, require_senior_or_admin

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])

@router.get("", response_model=List[AlertResponse])
def list_alerts(
    severity: Optional[str] = None,
    status_filter: Optional[str] = None,
    session_id: Optional[int] = None,
    user_id: Optional[int] = None,
    auth_data = Depends(get_current_user_and_session),
    db: Session = Depends(get_db)
):
    """
    Query behavioral security alerts.
    RBAC: Interns cannot access system security alerts (403).
    Senior developers can view limited/investigatory alerts.
    Admins have full visibility.
    """
    current_user, _ = auth_data
    if current_user.role == "intern":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: interns cannot access security alerts."
        )

    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity.lower())
    if status_filter:
        query = query.filter(Alert.status == status_filter.lower())
    if session_id:
        query = query.filter(Alert.session_id == session_id)
    if user_id:
        query = query.filter(Alert.user_id == user_id)


    return query.order_by(Alert.created_at.desc()).all()

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert(
    alert_id: int,
    auth_data = Depends(get_current_user_and_session),
    db: Session = Depends(get_db)
):
    current_user, _ = auth_data
    if current_user.role == "intern":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access forbidden")

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert

@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert_status(
    alert_id: int,
    update_data: AlertStatusUpdate,
    auth_data = Depends(get_current_user_and_session),
    db: Session = Depends(get_db)
):
    current_user, _ = auth_data
    if current_user.role not in ("admin", "senior_dev"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    alert.status = update_data.status.lower()
    db.commit()
    db.refresh(alert)
    return alert

@router.get("/users/{user_id}", response_model=List[AlertResponse])
def get_user_alerts(
    user_id: int,
    auth_data = Depends(get_current_user_and_session),
    db: Session = Depends(get_db)
):
    current_user, _ = auth_data
    if current_user.role not in ("admin", "senior_dev"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    alerts = db.query(Alert).filter(Alert.user_id == user_id).order_by(Alert.created_at.desc()).all()
    return alerts
