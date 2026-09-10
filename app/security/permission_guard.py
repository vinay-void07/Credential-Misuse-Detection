from fastapi import HTTPException, status
from app.security.rbac import is_action_allowed
from app.database.models import User

def check_permission(user: User, sensitivity: str, action: str) -> bool:
    """
    Verify if user has permission. If not, raises HTTP 403 Forbidden.
    """
    if not is_action_allowed(user.role, sensitivity, action):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Permission denied: role '{user.role}' cannot perform '{action}' on '{sensitivity}' resources."
        )
    return True
