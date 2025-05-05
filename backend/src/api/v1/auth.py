from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from starlette.requests import Request
from ...services.auth import create_user, login_user
from ...schemas.auth import UserCreate, UserResponse, Token, LoginRequest
from ...core.database import get_db
from ...core.oauth import oauth
from ...core.security import decode_access_token
from ...models.auth import User  # Added import
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Dependency to get the current user from a JWT token."""
    payload = decode_access_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate, db: Session = Depends(get_db)):
    """Register a new user."""
    return create_user(db, user)

@router.post("/login", response_model=Token)
async def login(login_data: LoginRequest, db: Session = Depends(get_db)):
    """Log in a user and return a JWT token."""
    return login_user(db, login_data.identifier, login_data.password)

@router.get("/google/login")
async def google_login(request: Request):
    """Initiate Google OAuth login."""
    redirect_uri = request.url_for('google_auth')
    logger.info("Initiating Google OAuth login")
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get("/google/auth", response_model=Token)
async def google_auth(request: Request, db: Session = Depends(get_db)):
    """Handle Google OAuth callback."""
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = token.get('userinfo')
        if not user_info:
            logger.error("Google OAuth failed: No user info")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Google auth failed")

        db_user = db.query(User).filter(User.email == user_info['email']).first()
        if not db_user:
            user_create = UserCreate(
                email=user_info['email'],
                full_name=user_info['name'],
                oauth_provider='google',
                oauth_id=user_info['sub'],
                oauth_access_token=token['access_token'],
                oauth_refresh_token=token.get('refresh_token')
            )
            db_user = create_user(db, user_create)
        else:
            # Update OAuth tokens
            db_auth = db.query(Auth).filter(Auth.user_id == db_user.id).first()
            db_auth.oauth_access_token = token['access_token']
            db_auth.oauth_refresh_token = token.get('refresh_token')
            db.commit()

        access_token = create_access_token(data={"sub": str(db_user.id)})
        logger.info(f"Google OAuth successful for: {db_user.email}")
        return Token(access_token=access_token, token_type="bearer")
    except Exception as e:
        logger.error(f"Google OAuth error: {str(e)}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="OAuth processing failed")

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get information about the current user."""
    return UserResponse.from_orm(current_user)