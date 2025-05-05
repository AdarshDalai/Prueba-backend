from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
from .config import settings
import logging

logger = logging.getLogger(__name__)

config = Config(environ={
    "GOOGLE_CLIENT_ID": settings.GOOGLE_CLIENT_ID,
    "GOOGLE_CLIENT_SECRET": settings.GOOGLE_CLIENT_SECRET,
    "APPLE_CLIENT_ID": settings.APPLE_CLIENT_ID,
    "APPLE_CLIENT_SECRET": settings.APPLE_CLIENT_SECRET
})

oauth = OAuth(config)

# Google OAuth configuration
oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Apple OAuth configuration (placeholder, requires additional setup)
oauth.register(
    name='apple',
    client_id=settings.APPLE_CLIENT_ID,
    client_secret=settings.APPLE_CLIENT_SECRET,
    authorize_url='https://appleid.apple.com/auth/authorize',
    access_token_url='https://appleid.apple.com/auth/token',
    client_kwargs={'scope': 'name email'}
)

logger.info("OAuth clients initialized for Google and Apple")