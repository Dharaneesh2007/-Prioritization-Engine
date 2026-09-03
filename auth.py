import bcrypt
from datetime import datetime, timedelta
from typing import Optional, Tuple
from fastapi import Request, HTTPException, Depends, status
from sqlalchemy.orm import Session
import uuid
import secrets

from models import User, UserRole, UserSession, AuthAuditLog
from database import get_db

SESSION_COOKIE_NAME = "soc_session"
DEFAULT_SESSION_DURATION_DAYS = 7
REMEMBER_ME_DURATION_DAYS = 30
RATE_LIMIT_WINDOW_MINUTES = 15
MAX_FAILED_ATTEMPTS_RATE_LIMIT = 5
MAX_FAILED_ATTEMPTS_LOCKOUT = 10

# --- Password Hashing ---

def hash_password(password: str) -> str:
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        pwd_bytes = plain_password.encode("utf-8")[:72]
        hashed_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pwd_bytes, hashed_bytes)
    except Exception:
        return False

# --- Session Management ---

def create_user_session(db: Session, user_id: str, remember_me: bool = True) -> UserSession:
    duration = timedelta(days=REMEMBER_ME_DURATION_DAYS if remember_me else DEFAULT_SESSION_DURATION_DAYS)
    expires_at = datetime.now() + duration
    
    session_id = secrets.token_urlsafe(32)
    session = UserSession(
        session_id=session_id,
        user_id=user_id,
        created_at=datetime.now(),
        expires_at=expires_at
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session

def get_user_session(db: Session, session_id: str) -> Optional[UserSession]:
    if not session_id:
        return None
    session = db.query(UserSession).filter(UserSession.session_id == session_id).first()
    if not session:
        return None
    if session.expires_at < datetime.now():
        db.delete(session)
        db.commit()
        return None
    return session

def invalidate_user_session(db: Session, session_id: str):
    if session_id:
        session = db.query(UserSession).filter(UserSession.session_id == session_id).first()
        if session:
            db.delete(session)
            db.commit()

# --- Audit Logging & Rate Limiting ---

def log_auth_event(
    db: Session,
    email: str,
    event_type: str,
    request: Optional[Request] = None
):
    ip_address = request.client.host if request and request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown") if request else "unknown"

    log = AuthAuditLog(
        email=email.lower().strip(),
        timestamp=datetime.now(),
        event_type=event_type,
        ip_address=ip_address,
        user_agent=user_agent
    )
    db.add(log)
    db.commit()

def check_login_rate_limit(db: Session, email: str) -> Tuple[bool, Optional[str]]:
    """
    Returns (is_allowed, error_message).
    Rate limits to 5 failed attempts per email per 15 minutes.
    """
    clean_email = email.lower().strip()
    window_start = datetime.now() - timedelta(minutes=RATE_LIMIT_WINDOW_MINUTES)
    
    recent_failed_attempts = db.query(AuthAuditLog).filter(
        AuthAuditLog.email == clean_email,
        AuthAuditLog.event_type == "LOGIN_FAILED",
        AuthAuditLog.timestamp >= window_start
    ).count()

    if recent_failed_attempts >= MAX_FAILED_ATTEMPTS_RATE_LIMIT:
        return False, "Too many failed login attempts. Rate limit reached. Please wait 15 minutes before trying again."

    return True, None

# --- FastAPI Authentication Dependencies ---

def get_current_user(
    request: Request,
    db: Session = Depends(get_db)
) -> User:
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )

    session = get_user_session(db, session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid"
        )

    user = db.query(User).filter(User.id == session.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is deactivated"
        )

    if user.locked_until and user.locked_until > datetime.now():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is locked due to excessive failed attempts. Please reset your password."
        )

    return user

def get_optional_current_user(
    request: Request,
    db: Session = Depends(get_db)
) -> Optional[User]:
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_id:
        return None
    session = get_user_session(db, session_id)
    if not session:
        return None
    user = db.query(User).filter(User.id == session.user_id).first()
    if not user or not user.is_active:
        return None
    return user

def require_role(required_role: str):
    def role_dependency(current_user: User = Depends(get_current_user)) -> User:
        user_role_val = current_user.role.value if hasattr(current_user.role, 'value') else str(current_user.role)
        if user_role_val != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Insufficient privileges (requires {required_role} role)"
            )
        return current_user
    return role_dependency
