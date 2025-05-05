from fastapi import APIRouter
import logging

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

@router.get("/health")
async def health_check():
    """Check the health of the backend service."""
    logger.info("Health check requested")
    return {"status": "healthy"}