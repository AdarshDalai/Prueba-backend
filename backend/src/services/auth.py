from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from ..models.auth import User, Auth
from ..schemas.auth import UserCreate, UserResponse, Token
from ..core.security import get_password_hash, verify_password, create_access_token
from typing import Optional
import logging

logger = logging.getLogger(__name__)

def create_user(db: Session, user: UserCreate) -> UserResponse:
    """Create a new user with associated auth credentials."""
    try:
        # Check for existing user
        existing_user = db.query(User).filter(User.email == user.email).first()
        if existing_user:
            logger.warning(f"Attempt to register existing email: {user.email}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

        # Create user
        db_user = User(email=user.email, full_name=user.full_name, role=user.role)
        db.add(db_user)
        db.commit()
        db.refresh(db_user)

        # Create auth record
        password_hash = get_password_hash(user.password) if user.password else None
        db_auth = Auth(
            user_id=db_user.id,
            username=user.username,
            email=user.email if user.email else None,
            phone=user.phone,
            password_hash=password_hash,
            oauth_provider=user.oauth_provider,
            oauth_id=user.oauth_id,
            oauth_access_token=user.oauth_access_token,
            oauth_refresh_token=user.oauth_refresh_token
        )
        db.add(db_auth)
        db.commit()
        logger.info(f"User created: {db_user.email}")
        return UserResponse.from_orm(db_user)
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create user")

def authenticate_user(db: Session, identifier: str, password: Optional[str] = None) -> Optional[User]:
    """Authenticate a user by username, email, or phone."""
    auth = db.query(Auth).filter(
        (Auth.username == identifier) |
        (Auth.email == identifier) |
        (Auth.phone == identifier)
    ).first()
    if not auth or (password and not verify_password(password, auth.password_hash)):
        logger.warning(f"Authentication failed for identifier: {identifier}")
        return None
    return db.query(User).filter(User.id == auth.user_id).first()

def login_user(db: Session, identifier: str, password: str) -> Token:
    """Log in a user and return a JWT token."""
    user = authenticate_user(db, identifier, password)
    if not user:
        logger.warning(f"Login failed for identifier: {identifier}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": str(user.id)})
    logger.info(f"User logged in: {user.email}")
    return Token(access_token=access_token, token_type="bearer")