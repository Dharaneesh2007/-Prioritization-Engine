from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, ForeignKey, Enum as SQLEnum
from sqlalchemy.orm import declarative_base, relationship
from enum import Enum
from datetime import datetime
import uuid

Base = declarative_base()

class Level(Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class Importance(Enum):
    STANDARD = "Standard"
    SENSITIVE = "Sensitive"
    CRITICAL = "Critical"

class Sensitivity(Enum):
    PUBLIC = "Public"
    INTERNAL = "Internal"
    CONFIDENTIAL = "Confidential"
    RESTRICTED = "Restricted"

class IncidentStatus(Enum):
    NEW = "New"
    INVESTIGATING = "Investigating"
    RESOLVED = "Resolved"
    MITIGATED = "Mitigated"
    CLOSED = "Closed"

class UserRole(Enum):
    ADMIN = "admin"
    ANALYST = "analyst"

class IncidentCluster(Base):
    __tablename__ = "incident_clusters"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(DateTime, default=datetime.now)
    primary_incident_id = Column(String, nullable=True) # ID of highest scoring incident in cluster
    incident_count = Column(Integer, default=1)
    combined_severity = Column(String, default="Medium")

    incidents = relationship("Incident", back_populates="cluster")

class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String, nullable=False)
    severity = Column(SQLEnum(Level), nullable=False)
    asset_importance = Column(SQLEnum(Importance), nullable=False)
    affected_users = Column(Integer, nullable=False)
    data_sensitivity = Column(SQLEnum(Sensitivity), nullable=False)
    attack_confidence = Column(Float, nullable=False)
    business_impact = Column(Float, nullable=False)
    status = Column(SQLEnum(IncidentStatus), default=IncidentStatus.NEW)
    assigned_to = Column(String, nullable=True)
    timestamp = Column(DateTime, default=datetime.now)

    # Phase 2 additions
    mitre_technique = Column(String, nullable=True) # e.g. "T1486"
    outcome = Column(String, nullable=True) # "Confirmed Threat" or "False Positive"
    investigating_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    playbook_progress = Column(String, default="[]") # JSON string of completed step IDs

    # Phase 3 Advanced additions
    cluster_id = Column(String, ForeignKey("incident_clusters.id"), nullable=True)
    source_ip = Column(String, nullable=True)
    target_asset = Column(String, nullable=True)
    asset_category = Column(String, default="default", nullable=True) # e.g. "database", "endpoint", "cloud", "default"

    audit_logs = relationship("AuditLog", back_populates="incident", cascade="all, delete-orphan")
    cluster = relationship("IncidentCluster", back_populates="incidents")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String, ForeignKey("incidents.id"))
    timestamp = Column(DateTime, default=datetime.now)
    action = Column(String, nullable=False) # e.g. "Status changed from New to Investigating"
    user = Column(String, nullable=True)

    incident = relationship("Incident", back_populates="audit_logs")

class SystemWeight(Base):
    __tablename__ = "system_weights"

    factor = Column(String, primary_key=True)
    weight = Column(Float, nullable=False)

class ScoringProfile(Base):
    __tablename__ = "scoring_profiles"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, unique=True, nullable=False) # e.g. "Database Servers", "Endpoints", "Default"
    asset_category = Column(String, unique=True, nullable=False) # e.g. "database", "endpoint", "cloud", "default"
    weights = Column(String, nullable=False) # JSON encoded factor weights dictionary
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.now)

class WebhookSubscription(Base):
    __tablename__ = "webhook_subscriptions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    url = Column(String, nullable=False)
    description = Column(String, nullable=True)
    secret = Column(String, nullable=False) # HMAC-SHA256 signature secret
    event_types = Column(String, nullable=False) # JSON list e.g. ["incident.created", "incident.critical", "incident.status_changed"]
    is_active = Column(Boolean, default=True)
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.now)

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(SQLEnum(UserRole), default=UserRole.ANALYST, nullable=False)
    created_at = Column(DateTime, default=datetime.now)
    last_login_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    reset_token = Column(String, nullable=True)
    reset_token_expires = Column(DateTime, nullable=True)

    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    saved_filters = relationship("SavedFilter", back_populates="user", cascade="all, delete-orphan")

class UserSession(Base):
    __tablename__ = "user_sessions"

    session_id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.now)
    expires_at = Column(DateTime, nullable=False)

    user = relationship("User", back_populates="sessions")

class AuthAuditLog(Base):
    __tablename__ = "auth_audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String, nullable=False)
    timestamp = Column(DateTime, default=datetime.now)
    event_type = Column(String, nullable=False) # e.g. LOGIN_SUCCESS, LOGIN_FAILED, ACCOUNT_LOCKED, LOGOUT
    ip_address = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)

class SavedFilter(Base):
    __tablename__ = "saved_filters"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    filter_json = Column(String, nullable=False) # JSON encoded filter criteria
    created_at = Column(DateTime, default=datetime.now)

    user = relationship("User", back_populates="saved_filters")
