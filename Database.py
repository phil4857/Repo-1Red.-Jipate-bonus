# database.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os

# ---------------- DATABASE URL ----------------
# Replace with your Render PostgreSQL URL
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://mkobawallet_user:HjhGTY2y8VBADx52gGS2Eom3mngX41lt@dpg-d6jesmdm5p6s73dnkda0-a.singapore-postgres.render.com/mkobawallet"
)

# ---------------- ENGINE ----------------
engine = create_engine(
    DATABASE_URL,
    connect_args={},  # Not needed for PostgreSQL
)

# ---------------- SESSION ----------------
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ---------------- BASE ----------------
Base = declarative_base()

# ---------------- DEPENDENCY ----------------
def get_db():
    """Provide a database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
