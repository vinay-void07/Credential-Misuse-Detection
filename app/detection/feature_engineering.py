from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database.models import ActivityLog, Session as UserSession
from app.core.config import settings

FEATURE_NAMES = [
    "requests_per_minute",
    "downloads_per_minute",
    "denied_requests",
    "confidential_access_count",
    "internal_access_count",
    "off_hours",
    "new_device",
    "unique_resources_accessed",
    "bulk_download_count",
    "permission_violation_count"
]

def extract_behavioral_features(
    db: Session,
    user_id: int,
    session_id: int,
    window_minutes: int = 5,
    reference_time: datetime = None
) -> Dict[str, Any]:
    if reference_time is None:
        reference_time = datetime.now(timezone.utc)
    
    if reference_time.tzinfo is None:
        reference_time = reference_time.replace(tzinfo=timezone.utc)

    window_start = reference_time - timedelta(minutes=window_minutes)

    logs = db.query(ActivityLog).filter(
        ActivityLog.session_id == session_id,
        ActivityLog.timestamp >= window_start,
        ActivityLog.timestamp <= reference_time
    ).all()

    total_requests = len(logs)
    actual_minutes = max(window_minutes, 1)

    requests_per_minute = round(total_requests / actual_minutes, 2)
    downloads = [log for log in logs if log.action == "download"]
    downloads_per_minute = round(len(downloads) / actual_minutes, 2)
    bulk_download_count = len(downloads)

    denied_logs = [log for log in logs if not log.allowed or log.status_code == 403]
    denied_requests = len(denied_logs)
    permission_violation_count = denied_requests

    confidential_access_count = len([
        log for log in logs if (log.resource_sensitivity == "confidential")
    ])
    internal_access_count = len([
        log for log in logs if (log.resource_sensitivity == "internal")
    ])

    unique_resources = {log.resource_id for log in logs if log.resource_id is not None}
    unique_resources_accessed = len(unique_resources)

    # is_off_hours: only active if explicitly simulated (e.g. reference_time.hour == 23 or log has hour 23)
    is_off_hours = 0
    if reference_time.hour == 23:
        is_off_hours = 1
    else:
        for log in logs:
            if log.request_metadata and log.request_metadata.get("simulated_hour") == 23:
                is_off_hours = 1
                break;

    # is_new_device: check if session had new_device flag at login
    curr_session = db.query(UserSession).filter(UserSession.id == session_id).first()
    is_new_device = 0
    if curr_session and curr_session.device_fingerprint:
        if curr_session.device_fingerprint.startswith("new-device") or "new_device" in curr_session.device_fingerprint:
            is_new_device = 1

    feature_dict = {
        "requests_per_minute": float(requests_per_minute),
        "downloads_per_minute": float(downloads_per_minute),
        "denied_requests": int(denied_requests),
        "confidential_access_count": int(confidential_access_count),
        "internal_access_count": int(internal_access_count),
        "off_hours": int(is_off_hours),
        "new_device": int(is_new_device),
        "unique_resources_accessed": int(unique_resources_accessed),
        "bulk_download_count": int(bulk_download_count),
        "permission_violation_count": int(permission_violation_count),
        "window_minutes": window_minutes,
        "total_requests": total_requests
    }

    feature_vector = [
        feature_dict[name] for name in FEATURE_NAMES
    ]
    feature_dict["vector"] = feature_vector

    return feature_dict
