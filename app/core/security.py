import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
import jwt
import bcrypt

from app.core.config import settings

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": now
    })
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate a JWT access token."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        return payload
    except (jwt.PyJWTError, Exception):
        return None

def generate_device_fingerprint(user_agent: Optional[str], client_device_id: Optional[str], ip_address: Optional[str]) -> str:
    """
    Generate a deterministic SHA-256 fingerprint from client metadata.
    Avoids invasive fingerprinting while reliably distinguishing devices.
    """
    raw_str = f"ua:{user_agent or 'unknown'}|dev:{client_device_id or 'default'}|ip:{ip_address or 'unknown'}"
    return hashlib.sha256(raw_str.encode("utf-8")).hexdigest()[:32]
