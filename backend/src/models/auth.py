from sqlalchemy import Column, Integer, String, DateTime, Enum, ForeignKey
from sqlalchemy.orm import relationship
from ..core.database import Base
from datetime import datetime
import enum

class Role(enum.Enum):
    user = "user"
    instructor = "instructor"
    admin = "admin"

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=True)
    username = Column(String, unique=True, nullable=True)
    phone = Column(String, nullable=True)
    hashed_password = Column(String, nullable=True)
    role = Column(Enum(Role), default=Role.user, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    auth = relationship("Auth", back_populates="user", uselist=False)

class Auth(Base):
    __tablename__ = "auth"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    oauth_provider = Column(String, nullable=True)
    oauth_id = Column(String, nullable=True)
    oauth_access_token = Column(String, nullable=True)
    oauth_refresh_token = Column(String, nullable=True)
    user = relationship("User", back_populates="auth")