from pydantic import BaseModel, EmailStr, validator
from typing import Optional
import re

class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None
    role: str = "user"

    @validator("role")
    def validate_role(cls, v):
        valid_roles = ["user", "instructor", "admin"]
        if v not in valid_roles:
            raise ValueError(f"Role must be one of {valid_roles}")
        return v

class UserCreate(UserBase):
    password: Optional[str] = None
    username: Optional[str] = None
    phone: Optional[str] = None
    oauth_provider: Optional[str] = None
    oauth_id: Optional[str] = None
    oauth_access_token: Optional[str] = None
    oauth_refresh_token: Optional[str] = None

    @validator("phone")
    def validate_phone(cls, v):
        if v and not re.match(r"^\+?[1-9]\d{1,14}$", v):
            raise ValueError("Invalid phone number format")
        return v

    @validator("username")
    def validate_username(cls, v):
        if v and (len(v) < 3 or len(v) > 50):
            raise ValueError("Username must be between 3 and 50 characters")
        return v

class UserResponse(UserBase):
    id: int
    created_at: str

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class LoginRequest(BaseModel):
    identifier: str  # username, email, or phone
    password: str