from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional

class ResourceCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    description: Optional[str] = None
    resource_type: str = Field("document", description="document, database, secret_store")
    sensitivity: str = Field("internal", description="public, internal, confidential")
    file_size_kb: Optional[int] = 128

class ResourceUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    sensitivity: Optional[str] = None

class ResourceResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    resource_type: str
    sensitivity: str
    owner_id: Optional[int]
    file_size_kb: int
    created_at: datetime

    class Config:
        from_attributes = True

class DownloadResponse(BaseModel):
    resource_id: int
    name: str
    sensitivity: str
    content_snippet: str
    file_size_kb: int
    download_timestamp: str
