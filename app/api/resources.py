from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timezone

from app.database.database import get_db
from app.database.models import Resource, User
from app.schemas.resources import ResourceCreate, ResourceUpdate, ResourceResponse, DownloadResponse
from app.core.dependencies import get_current_user_and_session
from app.security.permission_guard import check_permission

router = APIRouter(prefix="/resources", tags=["Resources"])

@router.get("", response_model=List[ResourceResponse])
def list_resources(
    sensitivity: Optional[str] = None,
    limit: int = 100,
    request: Request = None,
    auth_data = Depends(get_current_user_and_session),
    db: Session = Depends(get_db)
):
    """
    List available enterprise resources.
    Users can see listings, but attempting to read/download confidential resources
    will still be enforced by RBAC.
    """
    user, _ = auth_data
    query = db.query(Resource)
    if sensitivity:
        query = query.filter(Resource.sensitivity == sensitivity.lower())
    resources = query.limit(limit).all()
    return resources

@router.get("/{resource_id}", response_model=ResourceResponse)
def get_resource(
    resource_id: int,
    request: Request,
    auth_data = Depends(get_current_user_and_session),
    db: Session = Depends(get_db)
):
    """
    View details/content of a specific resource.
    RBAC is strictly enforced based on user role and resource sensitivity.
    """
    user, _ = auth_data
    resource = db.query(Resource).filter(Resource.id == resource_id).first()
    if not resource:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Resource with ID {resource_id} not found"
        )

    # Attach resource details to request state for activity logger
    request.state.resource_id = resource.id
    request.state.resource_sensitivity = resource.sensitivity

    # Check RBAC authorization
    check_permission(user, resource.sensitivity, "read")

    return resource

@router.get("/{resource_id}/download", response_model=DownloadResponse)
def download_resource(
    resource_id: int,
    request: Request,
    auth_data = Depends(get_current_user_and_session),
    db: Session = Depends(get_db)
):
    """
    Download resource file.
    Only authorized roles (senior_dev, admin for confidential; all for public/internal) can download.
    Unauthorized attempts are blocked and logged.
    """
    user, _ = auth_data
    resource = db.query(Resource).filter(Resource.id == resource_id).first()
    if not resource:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Resource with ID {resource_id} not found"
        )

    request.state.resource_id = resource.id
    request.state.resource_sensitivity = resource.sensitivity

    # Check RBAC authorization for download action
    check_permission(user, resource.sensitivity, "download")

    return DownloadResponse(
        resource_id=resource.id,
        name=resource.name,
        sensitivity=resource.sensitivity,
        content_snippet=f"[SECURE_CONTENT]: {resource.description or resource.name} payload bytes verified.",
        file_size_kb=resource.file_size_kb,
        download_timestamp=datetime.now(timezone.utc).isoformat()
    )

@router.post("", response_model=ResourceResponse, status_code=status.HTTP_201_CREATED)
def create_resource(
    resource_in: ResourceCreate,
    request: Request,
    auth_data = Depends(get_current_user_and_session),
    db: Session = Depends(get_db)
):
    """
    Create a new organizational resource.
    Interns cannot create confidential resources.
    """
    user, _ = auth_data
    check_permission(user, resource_in.sensitivity, "write")

    new_res = Resource(
        name=resource_in.name,
        description=resource_in.description,
        resource_type=resource_in.resource_type,
        sensitivity=resource_in.sensitivity.lower(),
        owner_id=user.id,
        file_size_kb=resource_in.file_size_kb or 128
    )
    db.add(new_res)
    db.commit()
    db.refresh(new_res)

    request.state.resource_id = new_res.id
    request.state.resource_sensitivity = new_res.sensitivity
    return new_res

@router.post("/{resource_id}/update", response_model=ResourceResponse)
def update_resource(
    resource_id: int,
    resource_update: ResourceUpdate,
    request: Request,
    auth_data = Depends(get_current_user_and_session),
    db: Session = Depends(get_db)
):
    """Update metadata or sensitivity of a resource."""
    user, _ = auth_data
    resource = db.query(Resource).filter(Resource.id == resource_id).first()
    if not resource:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found")

    request.state.resource_id = resource.id
    request.state.resource_sensitivity = resource.sensitivity

    check_permission(user, resource.sensitivity, "update")

    if resource_update.name is not None:
        resource.name = resource_update.name
    if resource_update.description is not None:
        resource.description = resource_update.description
    if resource_update.sensitivity is not None:
        resource.sensitivity = resource_update.sensitivity.lower()

    db.commit()
    db.refresh(resource)
    return resource
