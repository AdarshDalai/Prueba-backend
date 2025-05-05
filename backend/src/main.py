import logging
from fastapi import FastAPI
from .api.v1 import auth, health
from .core.database import Base, engine
from .core.config import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Prueba Backend",
    description="Backend API for prueba-backend quiz application",
    version="1.0.0"
)

# Create database tables
Base.metadata.create_all(bind=engine)

# Include API routers
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(health.router, prefix=settings.API_V1_STR)

@app.on_event("startup")
async def startup_event():
    logger.info("Starting prueba-backend...")