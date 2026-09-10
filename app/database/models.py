from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Float, ForeignKey, Text, JSON
)
from sqlalchemy.orm import relationship
from app.database.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False, default="intern")  # intern, senior_dev, admin
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    activity_logs = relationship("ActivityLog", back_populates="user", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="user", cascade="all, delete-orphan")

class Resource(Base):
    __tablename__ = "resources"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(128), nullable=False, index=True)
    description = Column(Text, nullable=True)
    resource_type = Column(String(64), nullable=False, default="document")  # document, database, secret_store
    sensitivity = Column(String(32), nullable=False, default="internal")   # public, internal, confidential
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    file_size_kb = Column(Integer, default=128)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    activity_logs = relationship("ActivityLog", back_populates="resource")

class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, index=True)
    role = Column(String(32), nullable=False, index=True)          # intern, senior_dev, admin
    sensitivity = Column(String(32), nullable=False, index=True)   # public, internal, confidential
    allowed_actions = Column(String(128), nullable=False)          # comma-separated: read,write,download,full

class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    session_token_id = Column(String(64), unique=True, index=True, nullable=False)
    ip_address = Column(String(64), nullable=True)
    device_fingerprint = Column(String(64), nullable=False, index=True)
    started_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_activity_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    risk_score = Column(Float, default=0.0, nullable=False)
    status = Column(String(32), default="active", nullable=False)  # active, terminated, expired, suspicious

    # Relationships
    user = relationship("User", back_populates="sessions")
    activity_logs = relationship("ActivityLog", back_populates="session", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="session", cascade="all, delete-orphan")

class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    endpoint = Column(String(255), nullable=False)
    action = Column(String(32), nullable=False)  # login, read, write, download, update, terminate
    resource_id = Column(Integer, ForeignKey("resources.id"), nullable=True)
    resource_sensitivity = Column(String(32), nullable=True)  # public, internal, confidential
    ip_address = Column(String(64), nullable=True)
    device_fingerprint = Column(String(64), nullable=True)
    allowed = Column(Boolean, nullable=False)
    status_code = Column(Integer, nullable=False)
    response_time = Column(Float, default=0.0)  # ms
    request_metadata = Column(JSON, nullable=True)

    # Relationships
    user = relationship("User", back_populates="activity_logs")
    session = relationship("Session", back_populates="activity_logs")
    resource = relationship("Resource", back_populates="activity_logs")

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=False, index=True)
    severity = Column(String(32), nullable=False, index=True)  # low, medium, high, critical
    risk_score = Column(Float, nullable=False)
    alert_type = Column(String(64), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    evidence = Column(JSON, nullable=False)
    recommended_action = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    status = Column(String(32), default="open", nullable=False)  # open, investigating, resolved

    # Relationships
    user = relationship("User", back_populates="alerts")
    session = relationship("Session", back_populates="alerts")
