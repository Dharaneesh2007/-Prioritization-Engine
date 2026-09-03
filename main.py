from fastapi import FastAPI, HTTPException, Depends, Query, Response, Request, status, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import uuid
import json
import os
import io
import csv
import secrets
import asyncio

from models import Incident, Level, Importance, Sensitivity, IncidentStatus, AuditLog, SystemWeight, User, UserRole, UserSession, AuthAuditLog, SavedFilter, IncidentCluster, WebhookSubscription, ScoringProfile, Base
from database import engine, get_db, init_db
from engine import PrioritizationEngine
from justifier import Justifier
import scoring
import storage
import auth
import mitre
import playbooks
import correlation
import webhooks
import generator
import knowledge_data

app = FastAPI(title="Cyber SOC Command Center")

# Initialize Database
try:
    init_db()
except Exception as e:
    print(f"Database init notice: {e}")

# Global Engine Instances
prioritizer = PrioritizationEngine()
justifier = Justifier()

WEIGHTS_CONFIG_FILE = "weights_config.json"

# --- Pydantic Models ---

class IncidentCreate(BaseModel):
    title: str
    severity: str
    asset_importance: str
    affected_users: int = Field(ge=1)
    data_sensitivity: str
    attack_confidence: float = Field(ge=0.0, le=1.0)
    business_impact: float = Field(ge=0.0, le=10.0)
    mitre_technique: Optional[str] = None
    source_ip: Optional[str] = None
    target_asset: Optional[str] = None
    asset_category: Optional[str] = "default"

class StatusUpdateRequest(BaseModel):
    status: str
    assigned_to: Optional[str] = None
    outcome: Optional[str] = None

class PlaybookProgressUpdate(BaseModel):
    completed_steps: List[int]

class BulkStatusUpdateRequest(BaseModel):
    incident_ids: List[str]
    status: str
    outcome: Optional[str] = None
    assigned_to: Optional[str] = None

class SavedFilterCreate(BaseModel):
    name: str
    filter_json: str

class SavedFilterResponse(BaseModel):
    id: str
    name: str
    filter_json: str
    created_at: str

class IncidentResponse(BaseModel):
    id: str
    title: str
    severity: str
    asset_importance: str
    affected_users: int
    data_sensitivity: str
    attack_confidence: float
    business_impact: float
    status: str
    assigned_to: Optional[str]
    score: float
    top_factor: Optional[str] = None
    timestamp: Optional[str] = None
    rank: Optional[int] = None
    mitre_technique: Optional[str] = None
    mitre_name: Optional[str] = None
    outcome: Optional[str] = None
    investigating_at: Optional[str] = None
    resolved_at: Optional[str] = None
    playbook_progress: Optional[List[int]] = None
    sla_breach: Optional[bool] = False
    cluster_id: Optional[str] = None
    cluster_incident_count: Optional[int] = None
    is_campaign_member: Optional[bool] = False
    source_ip: Optional[str] = None
    target_asset: Optional[str] = None
    asset_category: Optional[str] = "default"

class ScorePreviewRequest(BaseModel):
    severity: str
    asset_importance: str
    affected_users: int
    data_sensitivity: str
    attack_confidence: float
    business_impact: float
    asset_category: Optional[str] = "default"

class WeightUpdate(BaseModel):
    weights: Dict[str, float]

class ScoringProfileCreate(BaseModel):
    name: str
    asset_category: str
    weights: Dict[str, float]
    is_default: Optional[bool] = False

class ScoringProfileUpdate(BaseModel):
    weights: Dict[str, float]

class ScoringProfileResponse(BaseModel):
    id: str
    name: str
    asset_category: str
    weights: Dict[str, float]
    is_default: bool
    created_at: str

class WebhookCreate(BaseModel):
    url: str
    description: Optional[str] = None
    event_types: List[str]

class WebhookResponse(BaseModel):
    id: str
    url: str
    description: Optional[str]
    event_types: List[str]
    is_active: bool
    created_by: Optional[str]
    created_at: str
    secret: Optional[str] = None

class ClusterMemberSummary(BaseModel):
    id: str
    title: str
    severity: str
    score: float
    status: str
    source_ip: Optional[str] = None
    target_asset: Optional[str] = None
    timestamp: str

class ClusterResponse(BaseModel):
    id: str
    created_at: str
    primary_incident_id: Optional[str]
    incident_count: int
    combined_severity: str
    members: List[ClusterMemberSummary]

class LoginRequest(BaseModel):
    email: str
    password: str
    remember_me: bool = True

class RegisterRequest(BaseModel):
    email: str
    password: str
    role: Optional[str] = "analyst"

class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

class UserResponse(BaseModel):
    id: str
    email: str
    role: str
    created_at: str
    last_login_at: Optional[str] = None
    is_active: bool

# --- Helper Functions ---

def get_scoring_profiles_map(db: Session) -> Dict[str, Dict[str, float]]:
    profiles = db.query(ScoringProfile).all()
    if not profiles:
        return {"default": scoring.DEFAULT_WEIGHTS.copy()}
    
    mapping = {}
    for p in profiles:
        try:
            mapping[p.asset_category.lower()] = json.loads(p.weights)
        except Exception:
            mapping[p.asset_category.lower()] = scoring.DEFAULT_WEIGHTS.copy()
    return mapping

def get_current_weights(db: Session) -> Dict[str, float]:
    def_profile = db.query(ScoringProfile).filter(ScoringProfile.is_default == True).first()
    if def_profile:
        try:
            return json.loads(def_profile.weights)
        except Exception:
            pass

    weight_records = db.query(SystemWeight).all()
    if not weight_records:
        return scoring.DEFAULT_WEIGHTS.copy()
    return {r.factor: r.weight for r in weight_records}

def persist_weights_to_file(weights: Dict[str, float]):
    try:
        with open(WEIGHTS_CONFIG_FILE, "w") as f:
            json.dump(weights, f, indent=4)
    except Exception as e:
        print(f"Error saving weights config: {e}")

def sync_incidents_to_json(db: Session):
    try:
        incidents = db.query(Incident).all()
        storage.save_incidents(incidents)
    except Exception as e:
        print(f"Error syncing incidents to JSON: {e}")

def is_incident_sla_breach(inc: Incident) -> bool:
    if inc.severity == Level.CRITICAL and inc.status == IncidentStatus.NEW and inc.timestamp:
        return (datetime.now() - inc.timestamp).total_seconds() > 900 # 15 mins
    return False

def parse_playbook_progress(progress_str: Optional[str]) -> List[int]:
    if not progress_str:
        return []
    try:
        data = json.loads(progress_str)
        return [int(x) for x in data] if isinstance(data, list) else []
    except Exception:
        return []

def serialize_incident_for_webhook(inc: Incident, score: float) -> dict:
    return {
        "id": inc.id,
        "title": inc.title,
        "severity": inc.severity.value,
        "asset_importance": inc.asset_importance.value,
        "affected_users": inc.affected_users,
        "data_sensitivity": inc.data_sensitivity.value,
        "attack_confidence": inc.attack_confidence,
        "business_impact": inc.business_impact,
        "score": score,
        "status": inc.status.value,
        "outcome": inc.outcome,
        "source_ip": inc.source_ip,
        "target_asset": inc.target_asset,
        "asset_category": inc.asset_category,
        "mitre_technique": inc.mitre_technique,
        "timestamp": inc.timestamp.isoformat() if inc.timestamp else datetime.now().isoformat()
    }

# --- Startup Seeding ---

@app.on_event("startup")
def startup_seed():
    db = next(get_db())
    try:
        # 1. Seed Scoring Profiles if empty
        profile_count = db.query(ScoringProfile).count()
        if profile_count == 0:
            profiles_seed = [
                {
                    "name": "Default",
                    "asset_category": "default",
                    "weights": scoring.DEFAULT_WEIGHTS,
                    "is_default": True
                },
                {
                    "name": "Database Servers",
                    "asset_category": "database",
                    "weights": {
                        "severity": 0.20,
                        "asset_importance": 0.20,
                        "affected_users": 0.10,
                        "data_sensitivity": 0.30,
                        "attack_confidence": 0.10,
                        "business_impact": 0.10
                    },
                    "is_default": False
                },
                {
                    "name": "Endpoints & Workstations",
                    "asset_category": "endpoint",
                    "weights": {
                        "severity": 0.30,
                        "asset_importance": 0.10,
                        "affected_users": 0.25,
                        "data_sensitivity": 0.10,
                        "attack_confidence": 0.15,
                        "business_impact": 0.10
                    },
                    "is_default": False
                },
                {
                    "name": "Cloud Infrastructure",
                    "asset_category": "cloud",
                    "weights": {
                        "severity": 0.20,
                        "asset_importance": 0.25,
                        "affected_users": 0.15,
                        "data_sensitivity": 0.20,
                        "attack_confidence": 0.10,
                        "business_impact": 0.10
                    },
                    "is_default": False
                },
                {
                    "name": "Network Gateways",
                    "asset_category": "network",
                    "weights": {
                        "severity": 0.25,
                        "asset_importance": 0.25,
                        "affected_users": 0.20,
                        "data_sensitivity": 0.10,
                        "attack_confidence": 0.10,
                        "business_impact": 0.10
                    },
                    "is_default": False
                }
            ]

            for p in profiles_seed:
                db.add(ScoringProfile(
                    name=p["name"],
                    asset_category=p["asset_category"],
                    weights=json.dumps(p["weights"]),
                    is_default=p["is_default"]
                ))
            db.commit()

        # 2. Seed Default Users if empty
        user_count = db.query(User).count()
        if user_count == 0:
            admin_pwd = "AdminSOC#2026!"
            analyst_pwd = "AnalystSOC#2026!"

            admin_user = User(
                email="admin@soccommand.local",
                hashed_password=auth.hash_password(admin_pwd),
                role=UserRole.ADMIN,
                is_active=True
            )
            analyst_user = User(
                email="analyst@soccommand.local",
                hashed_password=auth.hash_password(analyst_pwd),
                role=UserRole.ANALYST,
                is_active=True
            )
            db.add(admin_user)
            db.add(analyst_user)
            db.commit()

            print("\n" + "="*70)
            print(">>> SOC COMMAND CENTER BOOTSTRAP CREDENTIALS INITIALIZED <<<")
            print(f"[*] Admin Account   : admin@soccommand.local    | Password: {admin_pwd}")
            print(f"[*] Analyst Account : analyst@soccommand.local  | Password: {analyst_pwd}")
            print("="*70 + "\n")

        # 3. Seed Incidents if empty
        count = db.query(Incident).count()
        if count == 0:
            now = datetime.now()
            shared_source_ip = "198.51.100.42"
            shared_target_asset = "dc01.corp.internal"

            seed_data = [
                {
                    "title": "Active Ransomware Exfiltration on Domain Controller",
                    "severity": Level.CRITICAL,
                    "asset_importance": Importance.CRITICAL,
                    "affected_users": 1500,
                    "data_sensitivity": Sensitivity.RESTRICTED,
                    "attack_confidence": 0.95,
                    "business_impact": 9.8,
                    "status": IncidentStatus.NEW,
                    "assigned_to": "Tier-3 SecOps",
                    "timestamp": now - timedelta(minutes=25),
                    "mitre_technique": "T1486",
                    "source_ip": shared_source_ip,
                    "target_asset": shared_target_asset,
                    "asset_category": "database",
                    "outcome": None,
                    "investigating_at": None,
                    "resolved_at": None,
                    "playbook_progress": "[]"
                },
                {
                    "title": "Cobalt Strike Beaconing from Domain Controller",
                    "severity": Level.CRITICAL,
                    "asset_importance": Importance.CRITICAL,
                    "affected_users": 1200,
                    "data_sensitivity": Sensitivity.RESTRICTED,
                    "attack_confidence": 0.92,
                    "business_impact": 9.2,
                    "status": IncidentStatus.INVESTIGATING,
                    "assigned_to": "Tier-3 SecOps",
                    "timestamp": now - timedelta(minutes=20),
                    "mitre_technique": "T1071",
                    "source_ip": shared_source_ip,
                    "target_asset": shared_target_asset,
                    "asset_category": "database",
                    "outcome": None,
                    "investigating_at": now - timedelta(minutes=15),
                    "resolved_at": None,
                    "playbook_progress": "[1]"
                },
                {
                    "title": "Unauthorized SQL Injection on Payment Gateway",
                    "severity": Level.CRITICAL,
                    "asset_importance": Importance.CRITICAL,
                    "affected_users": 450,
                    "data_sensitivity": Sensitivity.RESTRICTED,
                    "attack_confidence": 0.88,
                    "business_impact": 9.0,
                    "status": IncidentStatus.INVESTIGATING,
                    "assigned_to": "Sarah Chen",
                    "timestamp": now - timedelta(hours=1, minutes=12),
                    "mitre_technique": "T1190",
                    "source_ip": "203.0.113.88",
                    "target_asset": "api-gateway.pay.internal",
                    "asset_category": "cloud",
                    "outcome": None,
                    "investigating_at": now - timedelta(minutes=58),
                    "resolved_at": None,
                    "playbook_progress": "[1, 2]"
                },
                {
                    "title": "Compromised Admin Credentials with MFA Bypass",
                    "severity": Level.HIGH,
                    "asset_importance": Importance.SENSITIVE,
                    "affected_users": 120,
                    "data_sensitivity": Sensitivity.CONFIDENTIAL,
                    "attack_confidence": 0.85,
                    "business_impact": 7.5,
                    "status": IncidentStatus.INVESTIGATING,
                    "assigned_to": "Alex Mercer",
                    "timestamp": now - timedelta(hours=2, minutes=45),
                    "mitre_technique": "T1078",
                    "source_ip": "185.220.101.5",
                    "target_asset": "auth.corp.internal",
                    "asset_category": "endpoint",
                    "outcome": None,
                    "investigating_at": now - timedelta(hours=2, minutes=30),
                    "resolved_at": None,
                    "playbook_progress": "[1]"
                },
                {
                    "title": "Mass Phishing Campaign targeting Finance Dept",
                    "severity": Level.HIGH,
                    "asset_importance": Importance.SENSITIVE,
                    "affected_users": 85,
                    "data_sensitivity": Sensitivity.CONFIDENTIAL,
                    "attack_confidence": 0.75,
                    "business_impact": 6.2,
                    "status": IncidentStatus.NEW,
                    "assigned_to": None,
                    "timestamp": now - timedelta(hours=4, minutes=20),
                    "mitre_technique": "T1566",
                    "source_ip": "91.240.118.12",
                    "target_asset": "mail.corp.internal",
                    "asset_category": "endpoint",
                    "outcome": None,
                    "investigating_at": None,
                    "resolved_at": None,
                    "playbook_progress": "[]"
                },
                {
                    "title": "Sensitive S3 Cloud Bucket Public Read Policy",
                    "severity": Level.MEDIUM,
                    "asset_importance": Importance.SENSITIVE,
                    "affected_users": 15,
                    "data_sensitivity": Sensitivity.CONFIDENTIAL,
                    "attack_confidence": 0.90,
                    "business_impact": 5.5,
                    "status": IncidentStatus.RESOLVED,
                    "assigned_to": "DevSecOps Bot",
                    "timestamp": now - timedelta(hours=8, minutes=10),
                    "mitre_technique": "T1530",
                    "source_ip": "10.0.4.12",
                    "target_asset": "s3://invoices-production",
                    "asset_category": "cloud",
                    "outcome": "Confirmed Threat",
                    "investigating_at": now - timedelta(hours=7, minutes=55),
                    "resolved_at": now - timedelta(hours=7, minutes=20),
                    "playbook_progress": "[1, 2, 3, 4, 5]"
                }
            ]

            created_objs = []
            for item in seed_data:
                inc = Incident(
                    title=item["title"],
                    severity=item["severity"],
                    asset_importance=item["asset_importance"],
                    affected_users=item["affected_users"],
                    data_sensitivity=item["data_sensitivity"],
                    attack_confidence=item["attack_confidence"],
                    business_impact=item["business_impact"],
                    status=item["status"],
                    assigned_to=item["assigned_to"],
                    timestamp=item["timestamp"],
                    mitre_technique=item["mitre_technique"],
                    source_ip=item["source_ip"],
                    target_asset=item["target_asset"],
                    asset_category=item["asset_category"],
                    outcome=item["outcome"],
                    investigating_at=item["investigating_at"],
                    resolved_at=item["resolved_at"],
                    playbook_progress=item["playbook_progress"]
                )
                db.add(inc)
                db.commit()
                db.refresh(inc)
                created_objs.append(inc)

            # Correlate initial incidents into campaign cluster
            profiles_map = get_scoring_profiles_map(db)
            for inc in created_objs:
                correlation.correlate_and_cluster_incident(inc, db, profiles_map)

            sync_incidents_to_json(db)
    finally:
        db.close()

# Run startup seeding
try:
    startup_seed()
except Exception as e:
    print(f"Startup seeding notice: {e}")

# ==========================================
# AUTHENTICATION ENDPOINTS
# ==========================================

@app.post("/api/auth/login")
async def login(
    data: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    clean_email = data.email.lower().strip()

    is_allowed, rate_error = auth.check_login_rate_limit(db, clean_email)
    if not is_allowed:
        auth.log_auth_event(db, clean_email, "RATE_LIMIT_EXCEEDED", request)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=rate_error
        )

    user = db.query(User).filter(User.email == clean_email).first()

    if user and user.locked_until and user.locked_until > datetime.now():
        auth.log_auth_event(db, clean_email, "LOGIN_BLOCKED_LOCKED", request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is locked due to excessive failed attempts. Please reset your password."
        )

    valid = False
    if user and user.is_active:
        valid = auth.verify_password(data.password, user.hashed_password)

    if not valid:
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= auth.MAX_FAILED_ATTEMPTS_LOCKOUT:
                user.locked_until = datetime.now() + timedelta(hours=24)
                auth.log_auth_event(db, clean_email, "ACCOUNT_LOCKED", request)
            db.commit()

        auth.log_auth_event(db, clean_email, "LOGIN_FAILED", request)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or password"
        )

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.now()
    db.commit()

    auth.log_auth_event(db, clean_email, "LOGIN_SUCCESS", request)

    session = auth.create_user_session(db, user.id, data.remember_me)
    max_age_seconds = 86400 * (auth.REMEMBER_ME_DURATION_DAYS if data.remember_me else auth.DEFAULT_SESSION_DURATION_DAYS)

    response.set_cookie(
        key=auth.SESSION_COOKIE_NAME,
        value=session.session_id,
        httponly=True,
        samesite="lax",
        max_age=max_age_seconds,
        secure=False
    )

    return {
        "status": "success",
        "user": {
            "id": user.id,
            "email": user.email,
            "role": user.role.value,
            "created_at": user.created_at.isoformat() if user.created_at else "",
            "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None
        }
    }

@app.post("/api/auth/logout")
async def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    session_id = request.cookies.get(auth.SESSION_COOKIE_NAME)
    if session_id:
        auth.invalidate_user_session(db, session_id)
    
    response.delete_cookie(key=auth.SESSION_COOKIE_NAME)
    return {"status": "logged out"}

@app.get("/api/auth/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(auth.get_current_user)):
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        role=current_user.role.value,
        created_at=current_user.created_at.isoformat() if current_user.created_at else "",
        last_login_at=current_user.last_login_at.isoformat() if current_user.last_login_at else None,
        is_active=current_user.is_active
    )

@app.post("/api/auth/register", response_model=UserResponse)
async def register(
    data: RegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(auth.get_optional_current_user)
):
    clean_email = data.email.lower().strip()
    
    user_count = db.query(User).count()
    if user_count > 0:
        if not current_user or (current_user.role != UserRole.ADMIN and current_user.role.value != "admin"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only administrators can provision new user accounts."
            )

    exists = db.query(User).filter(User.email == clean_email).first()
    if exists:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists"
        )

    target_role = UserRole.ADMIN if data.role and data.role.lower() == "admin" else UserRole.ANALYST

    new_user = User(
        email=clean_email,
        hashed_password=auth.hash_password(data.password),
        role=target_role,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    auth.log_auth_event(db, clean_email, "USER_REGISTERED", request)

    return UserResponse(
        id=new_user.id,
        email=new_user.email,
        role=new_user.role.value,
        created_at=new_user.created_at.isoformat() if new_user.created_at else "",
        last_login_at=None,
        is_active=new_user.is_active
    )

@app.get("/api/auth/users", response_model=List[UserResponse])
async def list_users(
    db: Session = Depends(get_db),
    admin_user: User = Depends(auth.require_role("admin"))
):
    users = db.query(User).order_by(User.created_at.desc()).all()
    return [
        UserResponse(
            id=u.id,
            email=u.email,
            role=u.role.value,
            created_at=u.created_at.isoformat() if u.created_at else "",
            last_login_at=u.last_login_at.isoformat() if u.last_login_at else None,
            is_active=u.is_active
        )
        for u in users
    ]

@app.post("/api/auth/forgot-password")
async def forgot_password(
    data: ForgotPasswordRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    clean_email = data.email.lower().strip()
    user = db.query(User).filter(User.email == clean_email).first()

    if user and user.is_active:
        token = secrets.token_urlsafe(24)
        user.reset_token = token
        user.reset_token_expires = datetime.now() + timedelta(hours=1)
        db.commit()

        auth.log_auth_event(db, clean_email, "PASSWORD_RESET_REQUEST", request)

        print("\n" + "="*70)
        print("[TODO: WIRE UP EMAIL SERVICE - SENDGRID / AWS SES]")
        print(f"Password Reset Link Generated for: {clean_email}")
        print(f"Reset Token : {token}")
        print(f"Direct URL  : http://127.0.0.1:8000/static/index.html#reset-password?token={token}")
        print("="*70 + "\n")

    return {
        "status": "success",
        "message": "If that email address exists in our system, a password reset link has been dispatched."
    }

@app.post("/api/auth/reset-password")
async def reset_password(
    data: ResetPasswordRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    if not data.token or not data.new_password:
        raise HTTPException(status_code=400, detail="Token and new password are required")

    user = db.query(User).filter(
        User.reset_token == data.token,
        User.reset_token_expires > datetime.now()
    ).first()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    user.hashed_password = auth.hash_password(data.new_password)
    user.reset_token = None
    user.reset_token_expires = None
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    auth.log_auth_event(db, user.email, "PASSWORD_RESET_SUCCESS", request)

    return {"status": "success", "message": "Password updated successfully. You can now log in."}

# ==========================================
# CORRELATION & CAMPAIGN CLUSTERS (PHASE 3)
# ==========================================

@app.get("/api/clusters", response_model=List[ClusterResponse])
async def get_clusters(
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    profiles_map = get_scoring_profiles_map(db)
    clusters = db.query(IncidentCluster).order_by(IncidentCluster.created_at.desc()).all()
    results = []

    for c in clusters:
        members = db.query(Incident).filter(Incident.cluster_id == c.id).all()
        member_summaries = []
        for m in members:
            score = scoring.calculate_weighted_score(m, profiles_map)
            member_summaries.append(ClusterMemberSummary(
                id=m.id,
                title=m.title,
                severity=m.severity.value,
                score=score,
                status=m.status.value,
                source_ip=m.source_ip,
                target_asset=m.target_asset,
                timestamp=m.timestamp.isoformat() if m.timestamp else ""
            ))
        
        results.append(ClusterResponse(
            id=c.id,
            created_at=c.created_at.isoformat() if c.created_at else "",
            primary_incident_id=c.primary_incident_id,
            incident_count=len(members),
            combined_severity=c.combined_severity,
            members=member_summaries
        ))
    return results

@app.get("/api/clusters/{cluster_id}", response_model=ClusterResponse)
async def get_cluster_detail(
    cluster_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    c = db.query(IncidentCluster).filter(IncidentCluster.id == cluster_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Incident cluster not found")

    profiles_map = get_scoring_profiles_map(db)
    members = db.query(Incident).filter(Incident.cluster_id == c.id).all()
    member_summaries = []
    for m in members:
        score = scoring.calculate_weighted_score(m, profiles_map)
        member_summaries.append(ClusterMemberSummary(
            id=m.id,
            title=m.title,
            severity=m.severity.value,
            score=score,
            status=m.status.value,
            source_ip=m.source_ip,
            target_asset=m.target_asset,
            timestamp=m.timestamp.isoformat() if m.timestamp else ""
        ))

    return ClusterResponse(
        id=c.id,
        created_at=c.created_at.isoformat() if c.created_at else "",
        primary_incident_id=c.primary_incident_id,
        incident_count=len(members),
        combined_severity=c.combined_severity,
        members=member_summaries
    )

# ==========================================
# OUTBOUND WEBHOOKS (PHASE 3)
# ==========================================

@app.get("/api/webhooks", response_model=List[WebhookResponse])
async def list_webhooks(
    db: Session = Depends(get_db),
    admin_user: User = Depends(auth.require_role("admin"))
):
    subs = db.query(WebhookSubscription).order_by(WebhookSubscription.created_at.desc()).all()
    results = []
    for s in subs:
        try:
            ev_list = json.loads(s.event_types)
        except Exception:
            ev_list = []
        results.append(WebhookResponse(
            id=s.id,
            url=s.url,
            description=s.description,
            event_types=ev_list,
            is_active=s.is_active,
            created_by=s.created_by,
            created_at=s.created_at.isoformat() if s.created_at else "",
            secret=s.secret[:8] + "..." + s.secret[-4:] if s.secret else None
        ))
    return results

@app.post("/api/webhooks", response_model=WebhookResponse)
async def create_webhook(
    data: WebhookCreate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(auth.require_role("admin"))
):
    secret = webhooks.generate_webhook_secret()
    new_sub = WebhookSubscription(
        url=data.url.strip(),
        description=data.description.strip() if data.description else None,
        secret=secret,
        event_types=json.dumps(data.event_types),
        is_active=True,
        created_by=admin_user.email
    )
    db.add(new_sub)
    db.commit()
    db.refresh(new_sub)

    return WebhookResponse(
        id=new_sub.id,
        url=new_sub.url,
        description=new_sub.description,
        event_types=data.event_types,
        is_active=new_sub.is_active,
        created_by=new_sub.created_by,
        created_at=new_sub.created_at.isoformat(),
        secret=secret # Returned only once at creation!
    )

@app.delete("/api/webhooks/{webhook_id}")
async def delete_webhook(
    webhook_id: str,
    db: Session = Depends(get_db),
    admin_user: User = Depends(auth.require_role("admin"))
):
    sub = db.query(WebhookSubscription).filter(WebhookSubscription.id == webhook_id).first()
    if not sub:
        raise HTTPException(status_code=404, detail="Webhook subscription not found")
    db.delete(sub)
    db.commit()
    return {"status": "deleted"}

@app.post("/api/webhooks/{webhook_id}/test")
async def test_webhook(
    webhook_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    admin_user: User = Depends(auth.require_role("admin"))
):
    sub = db.query(WebhookSubscription).filter(WebhookSubscription.id == webhook_id).first()
    if not sub:
        raise HTTPException(status_code=404, detail="Webhook subscription not found")

    test_payload = {
        "event": "test.ping",
        "timestamp": datetime.now().isoformat(),
        "subscription_id": sub.id,
        "message": "SOC Command Center Webhook Connectivity Verification Ping"
    }

    background_tasks.add_task(
        webhooks.deliver_webhook_sync,
        sub.id,
        sub.url,
        sub.secret,
        "test.ping",
        test_payload
    )

    return {"status": "test dispatched", "target_url": sub.url}

# ==========================================
# SCORING PROFILES (PHASE 3)
# ==========================================

@app.get("/api/scoring-profiles", response_model=List[ScoringProfileResponse])
async def get_scoring_profiles(
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    profiles = db.query(ScoringProfile).order_by(ScoringProfile.is_default.desc(), ScoringProfile.name).all()
    results = []
    for p in profiles:
        try:
            w_dict = json.loads(p.weights)
        except Exception:
            w_dict = scoring.DEFAULT_WEIGHTS.copy()
        results.append(ScoringProfileResponse(
            id=p.id,
            name=p.name,
            asset_category=p.asset_category,
            weights=w_dict,
            is_default=p.is_default,
            created_at=p.created_at.isoformat() if p.created_at else ""
        ))
    return results

@app.post("/api/scoring-profiles", response_model=ScoringProfileResponse)
async def create_scoring_profile(
    data: ScoringProfileCreate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(auth.require_role("admin"))
):
    cat_clean = data.asset_category.lower().strip()
    exists = db.query(ScoringProfile).filter(
        (ScoringProfile.name == data.name.strip()) | (ScoringProfile.asset_category == cat_clean)
    ).first()
    if exists:
        raise HTTPException(status_code=400, detail="A profile with this name or asset category already exists")

    new_profile = ScoringProfile(
        name=data.name.strip(),
        asset_category=cat_clean,
        weights=json.dumps(data.weights),
        is_default=bool(data.is_default)
    )
    db.add(new_profile)
    db.commit()
    db.refresh(new_profile)

    return ScoringProfileResponse(
        id=new_profile.id,
        name=new_profile.name,
        asset_category=new_profile.asset_category,
        weights=data.weights,
        is_default=new_profile.is_default,
        created_at=new_profile.created_at.isoformat()
    )

@app.patch("/api/scoring-profiles/{profile_id}", response_model=ScoringProfileResponse)
async def update_scoring_profile_weights(
    profile_id: str,
    data: ScoringProfileUpdate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(auth.require_role("admin"))
):
    profile = db.query(ScoringProfile).filter(ScoringProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Scoring profile not found")

    profile.weights = json.dumps(data.weights)
    db.commit()
    db.refresh(profile)

    return ScoringProfileResponse(
        id=profile.id,
        name=profile.name,
        asset_category=profile.asset_category,
        weights=data.weights,
        is_default=profile.is_default,
        created_at=profile.created_at.isoformat()
    )

@app.delete("/api/scoring-profiles/{profile_id}")
async def delete_scoring_profile(
    profile_id: str,
    db: Session = Depends(get_db),
    admin_user: User = Depends(auth.require_role("admin"))
):
    profile = db.query(ScoringProfile).filter(ScoringProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Scoring profile not found")
    if profile.is_default:
        raise HTTPException(status_code=400, detail="Cannot delete the Default scoring profile")

    db.delete(profile)
    db.commit()
    return {"status": "deleted"}

@app.post("/api/scoring-profiles/{profile_id}/rescore")
async def rescore_profile_incidents(
    profile_id: str,
    db: Session = Depends(get_db),
    admin_user: User = Depends(auth.require_role("admin"))
):
    profile = db.query(ScoringProfile).filter(ScoringProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Scoring profile not found")

    weights_dict = json.loads(profile.weights)
    target_category = profile.asset_category.lower()

    if target_category == "default":
        matching_incidents = db.query(Incident).filter(
            (Incident.asset_category == "default") | (Incident.asset_category == None)
        ).all()
    else:
        matching_incidents = db.query(Incident).filter(
            Incident.asset_category == target_category
        ).all()

    for inc in matching_incidents:
        log = AuditLog(
            incident_id=inc.id,
            action=f"Rescored under profile '{profile.name}' ({profile.asset_category})",
            user=admin_user.email
        )
        db.add(log)
    db.commit()
    sync_incidents_to_json(db)

    return {
        "status": "rescored",
        "profile_name": profile.name,
        "asset_category": profile.asset_category,
        "affected_incidents_count": len(matching_incidents)
    }

# ==========================================
# MITRE ATT&CK ENDPOINTS
# ==========================================

@app.get("/api/mitre-techniques")
async def get_mitre_techniques(current_user: User = Depends(auth.get_current_user)):
    return mitre.get_all_mitre_techniques()

# ==========================================
# SAVED FILTER VIEWS ENDPOINTS
# ==========================================

@app.get("/api/saved-filters", response_model=List[SavedFilterResponse])
async def get_saved_filters(
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    filters = db.query(SavedFilter).filter(SavedFilter.user_id == current_user.id).order_by(SavedFilter.created_at.desc()).all()
    return [
        SavedFilterResponse(
            id=f.id,
            name=f.name,
            filter_json=f.filter_json,
            created_at=f.created_at.isoformat() if f.created_at else ""
        )
        for f in filters
    ]

@app.post("/api/saved-filters", response_model=SavedFilterResponse)
async def create_saved_filter(
    data: SavedFilterCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    new_filter = SavedFilter(
        user_id=current_user.id,
        name=data.name.strip(),
        filter_json=data.filter_json
    )
    db.add(new_filter)
    db.commit()
    db.refresh(new_filter)

    return SavedFilterResponse(
        id=new_filter.id,
        name=new_filter.name,
        filter_json=new_filter.filter_json,
        created_at=new_filter.created_at.isoformat()
    )

@app.delete("/api/saved-filters/{filter_id}")
async def delete_saved_filter(
    filter_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    f = db.query(SavedFilter).filter(SavedFilter.id == filter_id, SavedFilter.user_id == current_user.id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Saved filter not found")
    
    db.delete(f)
    db.commit()
    return {"status": "deleted"}

# ==========================================
# INCIDENT MANAGEMENT & PRIORITIZATION
# ==========================================

@app.get("/api/incidents", response_model=List[IncidentResponse])
async def get_incidents(
    status: Optional[str] = None,
    q: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    profiles_map = get_scoring_profiles_map(db)
    query = db.query(Incident)

    if status and status.lower() != "all":
        try:
            query = query.filter(Incident.status == IncidentStatus(status))
        except ValueError:
            pass

    incidents = query.all()

    if q and q.strip():
        search_term = q.strip().lower()
        incidents = [
            i for i in incidents 
            if search_term in i.title.lower() or 
               search_term in i.id.lower() or 
               (i.mitre_technique and search_term in i.mitre_technique.lower()) or
               (i.source_ip and search_term in i.source_ip.lower()) or
               (i.target_asset and search_term in i.target_asset.lower())
        ]

    ranked = prioritizer.rank_alerts(incidents, profiles_map)

    # Compute cluster sizes
    cluster_counts = {}
    for i in db.query(Incident).filter(Incident.cluster_id != None).all():
        cluster_counts[i.cluster_id] = cluster_counts.get(i.cluster_id, 0) + 1

    response = []
    for rank_idx, (inc, score) in enumerate(ranked, start=1):
        top_factor_str = scoring.get_top_factor(inc, profiles_map)
        breach = is_incident_sla_breach(inc)
        progress = parse_playbook_progress(inc.playbook_progress)
        c_count = cluster_counts.get(inc.cluster_id, 0)

        response.append(IncidentResponse(
            id=inc.id,
            title=inc.title,
            severity=inc.severity.value,
            asset_importance=inc.asset_importance.value,
            affected_users=inc.affected_users,
            data_sensitivity=inc.data_sensitivity.value,
            attack_confidence=inc.attack_confidence,
            business_impact=inc.business_impact,
            status=inc.status.value,
            assigned_to=inc.assigned_to,
            score=score,
            top_factor=top_factor_str,
            timestamp=inc.timestamp.isoformat() if inc.timestamp else datetime.now().isoformat(),
            rank=rank_idx,
            mitre_technique=inc.mitre_technique,
            mitre_name=mitre.get_mitre_name(inc.mitre_technique),
            outcome=inc.outcome,
            investigating_at=inc.investigating_at.isoformat() if inc.investigating_at else None,
            resolved_at=inc.resolved_at.isoformat() if inc.resolved_at else None,
            playbook_progress=progress,
            sla_breach=breach,
            cluster_id=inc.cluster_id,
            cluster_incident_count=c_count,
            is_campaign_member=c_count >= 2,
            source_ip=inc.source_ip,
            target_asset=inc.target_asset,
            asset_category=inc.asset_category or "default"
        ))
    return response

@app.post("/api/incidents/generate-shift-batch")
async def generate_shift_batch(
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    """
    Generates exact 100 realistic shift incidents featuring explicit showcase benchmark anchors
    and executes campaign graph correlation.
    """
    count = generator.generate_100_shift_incidents(db)
    correlation.correlate_and_cluster_incidents(db)
    sync_incidents_to_json(db)
    return {
        "status": "success",
        "count": count,
        "message": "100 realistic shift incidents ingested with explicit anchor benchmarks (INC-1042 vs INC-1018)."
    }

@app.get("/api/knowledge-docs")
async def get_knowledge_docs(
    current_user: Optional[User] = Depends(auth.get_optional_current_user)
):
    """
    Returns the comprehensive SOC knowledge base articles, formulas, and SOP playbooks.
    """
    return knowledge_data.get_all_knowledge_docs()

@app.get("/api/incidents/export")
async def export_incidents_csv(
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    profiles_map = get_scoring_profiles_map(db)
    incidents = db.query(Incident).all()
    ranked = prioritizer.rank_alerts(incidents, profiles_map)

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Rank",
        "Incident ID",
        "Title",
        "Priority Score",
        "Severity",
        "Asset Importance",
        "Asset Category",
        "Affected Users",
        "Data Sensitivity",
        "Attack Confidence",
        "Business Impact",
        "MITRE Technique",
        "Source IP",
        "Target Asset",
        "Campaign Cluster ID",
        "Status",
        "Outcome",
        "Assigned To",
        "Ingested Timestamp",
        "Investigating Timestamp",
        "Resolved Timestamp"
    ])

    for rank, (inc, score) in enumerate(ranked, start=1):
        writer.writerow([
            rank,
            inc.id,
            inc.title,
            score,
            inc.severity.value,
            inc.asset_importance.value,
            inc.asset_category or "default",
            inc.affected_users,
            inc.data_sensitivity.value,
            inc.attack_confidence,
            inc.business_impact,
            inc.mitre_technique or "N/A",
            inc.source_ip or "N/A",
            inc.target_asset or "N/A",
            inc.cluster_id or "N/A",
            inc.status.value,
            inc.outcome or "Pending",
            inc.assigned_to or "Unassigned",
            inc.timestamp.isoformat() if inc.timestamp else "",
            inc.investigating_at.isoformat() if inc.investigating_at else "",
            inc.resolved_at.isoformat() if inc.resolved_at else ""
        ])

    csv_content = output.getvalue()
    filename = f"soc_incidents_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.patch("/api/incidents/bulk-status")
async def bulk_update_status(
    data: BulkStatusUpdateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    if not data.incident_ids:
        raise HTTPException(status_code=400, detail="No incident IDs provided")

    try:
        new_status = IncidentStatus(data.status)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status: {data.status}")

    now = datetime.now()
    updated_count = 0
    profiles_map = get_scoring_profiles_map(db)

    for inc_id in data.incident_ids:
        inc = db.query(Incident).filter(Incident.id == inc_id).first()
        if not inc:
            continue

        old_status = inc.status.value
        inc.status = new_status
        if data.assigned_to:
            inc.assigned_to = data.assigned_to

        if new_status == IncidentStatus.INVESTIGATING and not inc.investigating_at:
            inc.investigating_at = now
        elif new_status in {IncidentStatus.RESOLVED, IncidentStatus.MITIGATED, IncidentStatus.CLOSED}:
            if not inc.resolved_at:
                inc.resolved_at = now
            if data.outcome:
                inc.outcome = data.outcome

        action_text = f"Bulk status update from '{old_status}' to '{new_status.value}'"
        if data.outcome:
            action_text += f" (Outcome: {data.outcome})"

        log = AuditLog(
            incident_id=inc.id,
            action=action_text,
            user=current_user.email
        )
        db.add(log)
        updated_count += 1

        # Dispatch status change webhook
        score = scoring.calculate_weighted_score(inc, profiles_map)
        wh_payload = {
            "event": "incident.status_changed",
            "old_status": old_status,
            "new_status": new_status.value,
            "incident": serialize_incident_for_webhook(inc, score),
            "updated_by": current_user.email
        }
        background_tasks.add_task(webhooks.dispatch_webhook, "incident.status_changed", wh_payload, get_db)

    db.commit()
    sync_incidents_to_json(db)

    return {
        "status": "bulk status updated",
        "updated_count": updated_count,
        "new_status": new_status.value
    }

@app.get("/api/incidents/{incident_id}")
async def get_incident_detail(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    profiles_map = get_scoring_profiles_map(db)
    score = scoring.calculate_weighted_score(inc, profiles_map)
    breakdown = scoring.get_factor_breakdown(inc, profiles_map)
    top_factor = scoring.get_top_factor(inc, profiles_map)
    
    playbook_data = playbooks.get_playbook_for_incident(inc)
    progress = parse_playbook_progress(inc.playbook_progress)

    # Cluster / Campaign Member Incidents
    related_campaign_members = []
    if inc.cluster_id:
        c_members = db.query(Incident).filter(Incident.cluster_id == inc.cluster_id).all()
        for m in c_members:
            m_score = scoring.calculate_weighted_score(m, profiles_map)
            related_campaign_members.append({
                "id": m.id,
                "title": m.title,
                "severity": m.severity.value,
                "score": m_score,
                "status": m.status.value,
                "source_ip": m.source_ip,
                "target_asset": m.target_asset,
                "timestamp": m.timestamp.isoformat() if m.timestamp else ""
            })

    # Compute current rank
    all_incidents = db.query(Incident).all()
    ranked = prioritizer.rank_alerts(all_incidents, profiles_map)
    rank_idx = next((i + 1 for i, (r_inc, _) in enumerate(ranked) if r_inc.id == inc.id), 1)

    # Get audit logs
    audit_records = db.query(AuditLog).filter(AuditLog.incident_id == incident_id).order_by(AuditLog.timestamp.desc()).all()
    logs = [
        {
            "id": l.id,
            "timestamp": l.timestamp.isoformat() if l.timestamp else "",
            "action": l.action,
            "user": l.user
        }
        for l in audit_records
    ]

    return {
        "id": inc.id,
        "title": inc.title,
        "severity": inc.severity.value,
        "asset_importance": inc.asset_importance.value,
        "affected_users": inc.affected_users,
        "data_sensitivity": inc.data_sensitivity.value,
        "attack_confidence": inc.attack_confidence,
        "business_impact": inc.business_impact,
        "status": inc.status.value,
        "assigned_to": inc.assigned_to,
        "score": score,
        "top_factor": top_factor,
        "rank": rank_idx,
        "total_ranked": len(ranked),
        "timestamp": inc.timestamp.isoformat() if inc.timestamp else datetime.now().isoformat(),
        "factor_breakdown": breakdown,
        "playbook": playbook_data,
        "playbook_progress": progress,
        "mitre_technique": inc.mitre_technique,
        "mitre_name": mitre.get_mitre_name(inc.mitre_technique),
        "outcome": inc.outcome,
        "investigating_at": inc.investigating_at.isoformat() if inc.investigating_at else None,
        "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
        "sla_breach": is_incident_sla_breach(inc),
        "cluster_id": inc.cluster_id,
        "campaign_members": related_campaign_members,
        "source_ip": inc.source_ip,
        "target_asset": inc.target_asset,
        "asset_category": inc.asset_category or "default",
        "audit_logs": logs
    }

@app.post("/api/incidents", response_model=IncidentResponse)
async def create_incident(
    inc_data: IncidentCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    try:
        new_inc = Incident(
            title=inc_data.title,
            severity=Level(inc_data.severity),
            asset_importance=Importance(inc_data.asset_importance),
            affected_users=inc_data.affected_users,
            data_sensitivity=Sensitivity(inc_data.data_sensitivity),
            attack_confidence=inc_data.attack_confidence,
            business_impact=inc_data.business_impact,
            status=IncidentStatus.NEW,
            mitre_technique=inc_data.mitre_technique.strip().upper() if inc_data.mitre_technique else None,
            source_ip=inc_data.source_ip.strip() if inc_data.source_ip else None,
            target_asset=inc_data.target_asset.strip() if inc_data.target_asset else None,
            asset_category=inc_data.asset_category.lower().strip() if inc_data.asset_category else "default",
            playbook_progress="[]"
        )

        db.add(new_inc)
        db.commit()
        db.refresh(new_inc)

        # 1. Run Correlation Engine to check for Campaign Clustering
        profiles_map = get_scoring_profiles_map(db)
        cluster = correlation.correlate_and_cluster_incident(new_inc, db, profiles_map)

        # 2. Audit Log
        mitre_label = f" (MITRE: {new_inc.mitre_technique})" if new_inc.mitre_technique else ""
        cluster_label = f" [Linked to Campaign Cluster {new_inc.cluster_id[:8]}]" if new_inc.cluster_id else ""
        log = AuditLog(
            incident_id=new_inc.id,
            action=f"Incident ingested into priority queue (Category: {new_inc.asset_category}, Severity: {new_inc.severity.value}{mitre_label}){cluster_label}",
            user=current_user.email
        )
        db.add(log)
        db.commit()

        score = scoring.calculate_weighted_score(new_inc, profiles_map)
        top_factor = scoring.get_top_factor(new_inc, profiles_map)

        sync_incidents_to_json(db)

        # 3. Webhook Notifications
        webhook_payload = {
            "event": "incident.created",
            "incident": serialize_incident_for_webhook(new_inc, score),
            "ingested_by": current_user.email
        }
        background_tasks.add_task(webhooks.dispatch_webhook, "incident.created", webhook_payload, get_db)

        if new_inc.severity == Level.CRITICAL:
            crit_payload = {
                "event": "incident.critical",
                "alert": "CRITICAL_DEFCON_TRIGGER",
                "incident": serialize_incident_for_webhook(new_inc, score)
            }
            background_tasks.add_task(webhooks.dispatch_webhook, "incident.critical", crit_payload, get_db)

        c_count = db.query(Incident).filter(Incident.cluster_id == new_inc.cluster_id).count() if new_inc.cluster_id else 0

        return IncidentResponse(
            id=new_inc.id,
            title=new_inc.title,
            severity=new_inc.severity.value,
            asset_importance=new_inc.asset_importance.value,
            affected_users=new_inc.affected_users,
            data_sensitivity=new_inc.data_sensitivity.value,
            attack_confidence=new_inc.attack_confidence,
            business_impact=new_inc.business_impact,
            status=new_inc.status.value,
            assigned_to=new_inc.assigned_to,
            score=score,
            top_factor=top_factor,
            timestamp=new_inc.timestamp.isoformat(),
            mitre_technique=new_inc.mitre_technique,
            mitre_name=mitre.get_mitre_name(new_inc.mitre_technique),
            outcome=None,
            playbook_progress=[],
            cluster_id=new_inc.cluster_id,
            cluster_incident_count=c_count,
            is_campaign_member=c_count >= 2,
            source_ip=new_inc.source_ip,
            target_asset=new_inc.target_asset,
            asset_category=new_inc.asset_category or "default"
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid input value: {str(e)}")

@app.patch("/api/incidents/{incident_id}/status")
async def update_status(
    incident_id: str,
    data: StatusUpdateRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    old_status = inc.status.value
    try:
        new_status = IncidentStatus(data.status)
        inc.status = new_status
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status value: {data.status}")

    now = datetime.now()
    if new_status == IncidentStatus.INVESTIGATING and not inc.investigating_at:
        inc.investigating_at = now
    elif new_status in {IncidentStatus.RESOLVED, IncidentStatus.MITIGATED, IncidentStatus.CLOSED}:
        if not inc.resolved_at:
            inc.resolved_at = now
        if data.outcome:
            inc.outcome = data.outcome

    if data.assigned_to is not None:
        inc.assigned_to = data.assigned_to.strip() if data.assigned_to.strip() else None

    # Audit log
    action_text = f"Status updated from '{old_status}' to '{inc.status.value}'"
    if inc.outcome:
        action_text += f" (Outcome: {inc.outcome})"
    if inc.assigned_to:
        action_text += f", assigned to {inc.assigned_to}"

    log = AuditLog(
        incident_id=incident_id,
        action=action_text,
        user=current_user.email
    )
    db.add(log)
    db.commit()
    sync_incidents_to_json(db)

    # Webhook Dispatch
    profiles_map = get_scoring_profiles_map(db)
    score = scoring.calculate_weighted_score(inc, profiles_map)
    wh_payload = {
        "event": "incident.status_changed",
        "old_status": old_status,
        "new_status": inc.status.value,
        "incident": serialize_incident_for_webhook(inc, score),
        "updated_by": current_user.email
    }
    background_tasks.add_task(webhooks.dispatch_webhook, "incident.status_changed", wh_payload, get_db)

    return {
        "status": "updated",
        "incident_id": incident_id,
        "new_status": inc.status.value,
        "outcome": inc.outcome,
        "assigned_to": inc.assigned_to,
        "investigating_at": inc.investigating_at.isoformat() if inc.investigating_at else None,
        "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None
    }

@app.patch("/api/incidents/{incident_id}/playbook-progress")
async def update_playbook_progress(
    incident_id: str,
    data: PlaybookProgressUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    inc.playbook_progress = json.dumps(data.completed_steps)
    
    log = AuditLog(
        incident_id=incident_id,
        action=f"Playbook checklist updated: {len(data.completed_steps)} steps marked complete",
        user=current_user.email
    )
    db.add(log)
    db.commit()
    sync_incidents_to_json(db)

    return {
        "status": "progress updated",
        "playbook_progress": data.completed_steps
    }

# --- Score Preview ---

class DraftIncident:
    def __init__(self, severity, asset_importance, affected_users, data_sensitivity, attack_confidence, business_impact, asset_category="default"):
        self.severity = Level(severity) if isinstance(severity, str) else severity
        self.asset_importance = Importance(asset_importance) if isinstance(asset_importance, str) else asset_importance
        self.affected_users = int(affected_users)
        self.data_sensitivity = Sensitivity(data_sensitivity) if isinstance(data_sensitivity, str) else data_sensitivity
        self.attack_confidence = float(attack_confidence)
        self.business_impact = float(business_impact)
        self.asset_category = asset_category

@app.get("/api/score-preview")
async def preview_score_get(
    severity: str = "Medium",
    asset_importance: str = "Standard",
    affected_users: int = 10,
    data_sensitivity: str = "Internal",
    attack_confidence: float = 0.5,
    business_impact: float = 5.0,
    asset_category: str = "default",
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    try:
        draft = DraftIncident(severity, asset_importance, affected_users, data_sensitivity, attack_confidence, business_impact, asset_category)
        profiles_map = get_scoring_profiles_map(db)
        score = scoring.calculate_weighted_score(draft, profiles_map)
        breakdown = scoring.get_factor_breakdown(draft, profiles_map)
        top_factor = scoring.get_top_factor(draft, profiles_map)

        return {
            "score": score,
            "top_factor": top_factor,
            "breakdown": breakdown,
            "resolved_weights": scoring.resolve_incident_weights(draft, profiles_map)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid preview parameters: {str(e)}")

@app.post("/api/score-preview")
async def preview_score_post(
    data: ScorePreviewRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    try:
        draft = DraftIncident(
            data.severity,
            data.asset_importance,
            data.affected_users,
            data.data_sensitivity,
            data.attack_confidence,
            data.business_impact,
            data.asset_category or "default"
        )
        profiles_map = get_scoring_profiles_map(db)
        score = scoring.calculate_weighted_score(draft, profiles_map)
        breakdown = scoring.get_factor_breakdown(draft, profiles_map)
        top_factor = scoring.get_top_factor(draft, profiles_map)

        return {
            "score": score,
            "top_factor": top_factor,
            "breakdown": breakdown,
            "resolved_weights": scoring.resolve_incident_weights(draft, profiles_map)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid preview payload: {str(e)}")

# --- Justification & Comparison ---

@app.get("/api/justify/{id1}/{id2}")
async def get_justification(
    id1: str,
    id2: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    inc_map = {inc.id: inc for inc in db.query(Incident).all()}

    if id1 not in inc_map or id2 not in inc_map:
        raise HTTPException(status_code=404, detail="One or both incidents not found")

    a = inc_map[id1]
    b = inc_map[id2]
    profiles_map = get_scoring_profiles_map(db)

    # Use incident A's weights for delta breakdown
    weights = scoring.resolve_incident_weights(a, profiles_map)
    comparison_data = justifier.generate_comparison_data(a, b, weights)
    return comparison_data

@app.get("/api/playbook/{incident_id}")
async def get_playbook(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    pb = playbooks.get_playbook_for_incident(inc)
    progress = parse_playbook_progress(inc.playbook_progress)
    return {"playbook": pb, "playbook_progress": progress}

# --- Legacy Global Weights Management (Admin Protected) ---

@app.get("/api/weights/presets")
async def get_weight_presets(
    current_user: User = Depends(auth.get_current_user)
):
    return scoring.PRESET_WEIGHTS

@app.get("/api/weights")
async def get_weights(
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    return get_current_weights(db)

@app.post("/api/weights")
@app.patch("/api/weights")
async def update_weights(
    data: WeightUpdate,
    db: Session = Depends(get_db),
    admin_user: User = Depends(auth.require_role("admin"))
):
    weights = data.weights
    for factor, weight in weights.items():
        record = db.query(SystemWeight).filter(SystemWeight.factor == factor).first()
        if record:
            record.weight = weight
        else:
            db.add(SystemWeight(factor=factor, weight=weight))

    # Also update default profile
    def_profile = db.query(ScoringProfile).filter(ScoringProfile.is_default == True).first()
    if def_profile:
        def_profile.weights = json.dumps(weights)

    db.commit()

    current = get_current_weights(db)
    persist_weights_to_file(current)

    return {"status": "weights updated", "weights": current}

@app.post("/api/weights/reset")
async def reset_weights(
    db: Session = Depends(get_db),
    admin_user: User = Depends(auth.require_role("admin"))
):
    for factor, weight in scoring.DEFAULT_WEIGHTS.items():
        record = db.query(SystemWeight).filter(SystemWeight.factor == factor).first()
        if record:
            record.weight = weight
        else:
            db.add(SystemWeight(factor=factor, weight=weight))

    def_profile = db.query(ScoringProfile).filter(ScoringProfile.is_default == True).first()
    if def_profile:
        def_profile.weights = json.dumps(scoring.DEFAULT_WEIGHTS)

    db.commit()

    current = scoring.DEFAULT_WEIGHTS.copy()
    persist_weights_to_file(current)

    return {"status": "weights reset to defaults", "weights": current}

# --- Analytics Summary ---

@app.get("/api/analytics/summary")
async def get_analytics_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    incidents = db.query(Incident).all()
    profiles_map = get_scoring_profiles_map(db)
    ranked = prioritizer.rank_alerts(incidents, profiles_map)

    total_incidents = len(incidents)
    resolved_statuses = {IncidentStatus.RESOLVED, IncidentStatus.MITIGATED, IncidentStatus.CLOSED}
    active_incidents = sum(1 for i in incidents if i.status not in resolved_statuses)
    resolved_count = sum(1 for i in incidents if i.status in resolved_statuses)

    scores = [score for _, score in ranked]
    avg_score = round(sum(scores) / len(scores), 2) if scores else 0.0

    now = datetime.now()
    twenty_four_hours_ago = now - timedelta(hours=24)
    alerts_today = sum(1 for i in incidents if i.timestamp and i.timestamp >= twenty_four_hours_ago)

    # 1. Severity distribution
    severity_dist = {
        "Critical": sum(1 for i in incidents if i.severity == Level.CRITICAL),
        "High": sum(1 for i in incidents if i.severity == Level.HIGH),
        "Medium": sum(1 for i in incidents if i.severity == Level.MEDIUM),
        "Low": sum(1 for i in incidents if i.severity == Level.LOW),
    }

    # 2. Status distribution
    status_dist = {
        "New": sum(1 for i in incidents if i.status == IncidentStatus.NEW),
        "Investigating": sum(1 for i in incidents if i.status == IncidentStatus.INVESTIGATING),
        "Resolved": sum(1 for i in incidents if i.status == IncidentStatus.RESOLVED),
        "Mitigated": sum(1 for i in incidents if i.status == IncidentStatus.MITIGATED),
        "Closed": sum(1 for i in incidents if i.status == IncidentStatus.CLOSED),
    }

    # 3. Asset Importance distribution
    asset_dist = {
        "Critical": sum(1 for i in incidents if i.asset_importance == Importance.CRITICAL),
        "Sensitive": sum(1 for i in incidents if i.asset_importance == Importance.SENSITIVE),
        "Standard": sum(1 for i in incidents if i.asset_importance == Importance.STANDARD),
    }

    # 4. Accuracy & False Positive Metrics
    confirmed_threats = sum(1 for i in incidents if i.outcome == "Confirmed Threat")
    false_positives = sum(1 for i in incidents if i.outcome == "False Positive")
    total_evaluated = confirmed_threats + false_positives
    accuracy_rate = round((confirmed_threats / total_evaluated * 100), 1) if total_evaluated > 0 else 100.0

    accuracy_by_severity = {}
    for sev_name, sev_enum in [("Critical", Level.CRITICAL), ("High", Level.HIGH), ("Medium", Level.MEDIUM), ("Low", Level.LOW)]:
        sev_incidents = [i for i in incidents if i.severity == sev_enum]
        conf = sum(1 for i in sev_incidents if i.outcome == "Confirmed Threat")
        fp = sum(1 for i in sev_incidents if i.outcome == "False Positive")
        tot = conf + fp
        rate = round((conf / tot * 100), 1) if tot > 0 else (100.0 if conf > 0 else 0.0)
        accuracy_by_severity[sev_name] = {
            "confirmed": conf,
            "false_positives": fp,
            "accuracy_rate": rate
        }

    # 5. SLA & Response Time Metrics
    tti_list = []
    ttr_list = []
    sla_breaches_count = 0

    for i in incidents:
        if is_incident_sla_breach(i):
            sla_breaches_count += 1

        if i.timestamp:
            if i.investigating_at and i.investigating_at >= i.timestamp:
                tti_list.append((i.investigating_at - i.timestamp).total_seconds() / 60)
            if i.resolved_at and i.resolved_at >= i.timestamp:
                ttr_list.append((i.resolved_at - i.timestamp).total_seconds() / 60)

    avg_tti_mins = round(sum(tti_list) / len(tti_list), 1) if tti_list else 12.0
    avg_ttr_mins = round(sum(ttr_list) / len(ttr_list), 1) if ttr_list else 45.0

    # 6. Top MITRE ATT&CK Techniques Distribution
    mitre_counts = {}
    for i in incidents:
        if i.mitre_technique:
            tech_id = i.mitre_technique.upper()
            tech_name = mitre.get_mitre_name(tech_id)
            label = f"{tech_id}: {tech_name}"
            mitre_counts[label] = mitre_counts.get(label, 0) + 1

    top_mitre = sorted(
        [{"technique": k, "count": v} for k, v in mitre_counts.items()],
        key=lambda x: x["count"],
        reverse=True
    )

    # 7. Score Histogram Bins
    score_bins = [
        {"range": "0 - 2.0", "count": sum(1 for s in scores if s < 2.0)},
        {"range": "2.0 - 4.0", "count": sum(1 for s in scores if 2.0 <= s < 4.0)},
        {"range": "4.0 - 6.0", "count": sum(1 for s in scores if 4.0 <= s < 6.0)},
        {"range": "6.0 - 8.0", "count": sum(1 for s in scores if 6.0 <= s < 8.0)},
        {"range": "8.0 - 10.0", "count": sum(1 for s in scores if s >= 8.0)},
    ]

    # 8. 24h Hourly Trend
    hourly_trend = []
    for h in range(23, -1, -1):
        slot_time = now - timedelta(hours=h)
        slot_label = slot_time.strftime("%H:00")
        start_slot = now - timedelta(hours=h + 1)
        end_slot = now - timedelta(hours=h)
        count_in_slot = sum(1 for i in incidents if i.timestamp and start_slot <= i.timestamp < end_slot)
        hourly_trend.append({"hour": slot_label, "count": count_in_slot})

    # 9. Active vs Resolved Timeline
    trend_intervals = []
    for d in range(4, -1, -1):
        day_date = (now - timedelta(days=d)).strftime("%b %d")
        cutoff = now - timedelta(days=d)
        active_then = sum(1 for i in incidents if i.timestamp and i.timestamp <= cutoff and i.status not in resolved_statuses)
        resolved_then = sum(1 for i in incidents if i.timestamp and i.timestamp <= cutoff and i.status in resolved_statuses)
        trend_intervals.append({
            "label": day_date,
            "active": active_then,
            "resolved": resolved_then
        })

    # Top Incident Summary
    top_incident_summary = None
    if ranked:
        top_inc, top_score = ranked[0]
        top_factor_str = scoring.get_top_factor(top_inc, profiles_map)
        breakdown = scoring.get_factor_breakdown(top_inc, profiles_map)
        sorted_factors = sorted(breakdown.values(), key=lambda x: x["contribution"], reverse=True)
        top1 = sorted_factors[0]
        top2 = sorted_factors[1]
        rationale = f"Top priority ({top_score}/10) due to {top1['label']} ({top1['raw']}) and {top2['label']} ({top2['raw']})"

        top_incident_summary = {
            "id": top_inc.id,
            "title": top_inc.title,
            "score": top_score,
            "severity": top_inc.severity.value,
            "asset_importance": top_inc.asset_importance.value,
            "top_factor": top_factor_str,
            "rationale": rationale,
            "mitre_technique": top_inc.mitre_technique,
            "mitre_name": mitre.get_mitre_name(top_inc.mitre_technique),
            "sla_breach": is_incident_sla_breach(top_inc),
            "cluster_id": top_inc.cluster_id,
            "asset_category": top_inc.asset_category or "default"
        }

    return {
        "total_incidents": total_incidents,
        "active_incidents": active_incidents,
        "resolved_incidents": resolved_count,
        "critical_count": severity_dist["Critical"],
        "high_count": severity_dist["High"],
        "avg_score": avg_score,
        "alerts_today": alerts_today,
        "severity_distribution": severity_dist,
        "status_distribution": status_dist,
        "asset_distribution": asset_dist,
        "score_distribution": score_bins,
        "hourly_trend": hourly_trend,
        "active_vs_resolved_trend": trend_intervals,
        "top_incident": top_incident_summary,
        "accuracy_rate": accuracy_rate,
        "confirmed_threats": confirmed_threats,
        "false_positives": false_positives,
        "accuracy_by_severity": accuracy_by_severity,
        "avg_tti_mins": avg_tti_mins,
        "avg_ttr_mins": avg_ttr_mins,
        "sla_breaches_count": sla_breaches_count,
        "top_mitre_techniques": top_mitre
    }

@app.get("/api/audit")
async def get_audit_logs(
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.get_current_user)
):
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(100).all()
    return [
        {
            "id": l.id,
            "timestamp": l.timestamp.isoformat() if l.timestamp else "",
            "incident_id": l.incident_id,
            "action": l.action,
            "user": l.user
        }
        for l in logs
    ]

# --- Static Frontend Mount ---
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
async def read_root():
    return RedirectResponse(url="/static/index.html")

