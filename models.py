# models.py
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

# ---------------- USER ----------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    phone = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    approved = Column(Boolean, default=False)
    balance = Column(Float, default=10000.0)
    earnings = Column(Float, default=0.0)
    referral = Column(String, nullable=True)
    bonus_days_remaining = Column(Integer, default=0)

    investments = relationship("Investment", back_populates="user", cascade="all, delete")
    withdrawals = relationship("Withdrawal", back_populates="user", cascade="all, delete")


# ---------------- INVESTMENT ----------------
class Investment(Base):
    __tablename__ = "investments"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    commodity = Column(String, nullable=False)
    amount = Column(Float, nullable=False)
    start_date = Column(DateTime, default=datetime.utcnow)
    expiry_date = Column(DateTime)

    user = relationship("User", back_populates="investments")


# ---------------- WITHDRAWAL ----------------
class Withdrawal(Base):
    __tablename__ = "withdrawals"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    amount = Column(Float, nullable=False)
    request_date = Column(DateTime, default=datetime.utcnow)
    approved = Column(Boolean, default=False)
    approved_by_admin = Column(String, nullable=True)

    user = relationship("User", back_populates="withdrawals")


# ---------------- ADMIN ----------------
class Admin(Base):
    __tablename__ = "admins"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
