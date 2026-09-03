import os
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from models import Base

# If running on Vercel serverless, use the writable /tmp directory for SQLite
if os.environ.get("VERCEL"):
    DATABASE_URL = "sqlite:////tmp/cyber_soc.db"
else:
    DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./cyber_soc.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

    # SQLite dynamic column migration helper
    with engine.connect() as conn:
        # Check and add Incident columns
        cursor = conn.execute(text("PRAGMA table_info(incidents);"))
        existing_cols = {row[1] for row in cursor.fetchall()}

        col_defs = {
            "mitre_technique": "VARCHAR",
            "outcome": "VARCHAR",
            "investigating_at": "DATETIME",
            "resolved_at": "DATETIME",
            "playbook_progress": "VARCHAR DEFAULT '[]'",
            "cluster_id": "VARCHAR",
            "source_ip": "VARCHAR",
            "target_asset": "VARCHAR",
            "asset_category": "VARCHAR DEFAULT 'default'"
        }

        for col_name, col_type in col_defs.items():
            if col_name not in existing_cols:
                try:
                    conn.execute(text(f"ALTER TABLE incidents ADD COLUMN {col_name} {col_type};"))
                    conn.commit()
                except Exception as e:
                    print(f"Column {col_name} migration note: {e}")

        # Check and add User columns if missing
        cursor_u = conn.execute(text("PRAGMA table_info(users);"))
        existing_user_cols = {row[1] for row in cursor_u.fetchall()}

        user_col_defs = {
            "failed_login_attempts": "INTEGER DEFAULT 0",
            "locked_until": "DATETIME",
            "reset_token": "VARCHAR",
            "reset_token_expires": "DATETIME"
        }

        for col_name, col_type in user_col_defs.items():
            if col_name not in existing_user_cols:
                try:
                    conn.execute(text(f"ALTER TABLE users ADD COLUMN {col_name} {col_type};"))
                    conn.commit()
                except Exception as e:
                    print(f"User column {col_name} migration note: {e}")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
