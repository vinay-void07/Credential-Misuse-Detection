import time
import logging
from datetime import datetime, timezone
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session

from app.database.database import SessionLocal
from app.database.models import ActivityLog
from app.detection.risk_engine import risk_engine
from app.core.security import generate_device_fingerprint, decode_access_token

logger = logging.getLogger("rism-network.middleware")

class ActivityLoggerMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time.perf_counter()
        
        user_agent = request.headers.get("user-agent", "unknown")
        client_device_id = request.headers.get("x-device-id")
        client_ip = request.client.host if request.client else "127.0.0.1"
        device_fingerprint = generate_device_fingerprint(user_agent, client_device_id, client_ip)

        simulated_hour = request.headers.get("x-simulated-hour")
        now_time = datetime.now(timezone.utc)
        hour_val = None
        if simulated_hour is not None:
            try:
                hour_val = int(simulated_hour)
                now_time = now_time.replace(hour=hour_val, minute=0, second=0)
            except Exception:
                pass

        auth_header = request.headers.get("authorization")
        extracted_user_id = None
        extracted_session_id = None
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            payload = decode_access_token(token)
            if payload:
                extracted_user_id = payload.get("user_id")
                extracted_session_id = payload.get("session_id")

        try:
            response: Response = await call_next(request)
            status_code = response.status_code
        except Exception as exc:
            status_code = 500
            raise exc
        finally:
            path = request.url.path
            if path.startswith("/api/"):
                duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
                method = request.method

                if "/auth/login" in path:
                    action = "login"
                elif "/auth/register" in path:
                    action = "register"
                elif "/download" in path:
                    action = "download"
                elif "/update" in path or method in ("PATCH", "PUT"):
                    action = "update"
                elif method == "POST":
                    action = "write"
                elif method == "DELETE":
                    action = "delete"
                else:
                    action = "read"

                allowed = (200 <= status_code < 400)

                current_user = getattr(request.state, "current_user", None)
                current_session = getattr(request.state, "current_session", None)

                user_id = current_user.id if current_user else extracted_user_id
                session_id = current_session.id if current_session else extracted_session_id

                resource_id = getattr(request.state, "resource_id", None)
                resource_sensitivity = getattr(request.state, "resource_sensitivity", None)

                db_factory = getattr(request.app.state, "db_factory", SessionLocal)
                db: Session = db_factory()
                try:
                    activity_record = ActivityLog(
                        user_id=user_id,
                        session_id=session_id,
                        timestamp=now_time,
                        endpoint=path,
                        action=action,
                        resource_id=resource_id,
                        resource_sensitivity=resource_sensitivity,
                        ip_address=client_ip,
                        device_fingerprint=device_fingerprint,
                        allowed=allowed,
                        status_code=status_code,
                        response_time=duration_ms,
                        request_metadata={
                            "method": method,
                            "user_agent": user_agent[-128:],
                            "client_device_id": client_device_id,
                            "simulated_hour": hour_val
                        }
                    )
                    db.add(activity_record)
                    db.commit()
                    db.refresh(activity_record)

                    if user_id and session_id:
                        risk_engine.evaluate_and_alert(
                            db=db,
                            user_id=user_id,
                            session_id=session_id,
                            latest_activity=activity_record,
                            reference_time=now_time
                        )
                except Exception as e:
                    logger.error(f"Failed to record activity log: {e}", exc_info=True)
                    db.rollback()
                finally:
                    db.close()

        return response
