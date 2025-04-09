"""
# Inter-Service Token Validation Module

## Purpose
This module provides a secure endpoint for validating user tokens across different microservices
in the application architecture. It acts as a central authentication verification point that other
services can rely on to confirm user identity and permissions.

## Functionality
- Validates user authentication tokens provided by other services
- Enforces service-level authorization via service tokens
- Manages user session timeouts based on idle time
- Implements secure token verification with multiple validation layers

## Flow
1. Receive verification request containing service token and user token
2. Validate that the requesting service is authorized
3. Locate the user associated with the provided token
4. Verify token authenticity by decoding with user's secret
5. Confirm token payload matches the expected user
6. Check for session timeout due to inactivity
7. Update idle time and return user details on success

## Security
- Uses 404 responses to hide endpoint existence from unauthorized requests
- Implements rate limiting to prevent brute force attacks
- Automatically invalidates compromised tokens
- Resets user authentication on any security breach
- Times out inactive sessions based on configured idle time

## Dependencies
- FastAPI: Web framework for API endpoints
- SQLAlchemy: Database ORM for user data access
- SlowAPI: Rate limiting implementation
- Custom security utilities: For token decoding and verification

## Usage
This endpoint is called by other microservices when they need to verify a user's identity.
Services must provide both their service token and the user's token in the request.

## Endpoints
- POST /verify: Verifies user token and returns user information on success
"""

from datetime import datetime
# Removed unused timedelta import
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from app.utils.db import get_db
from app.models.users_table import User
from app.schemas.token import TokenVerify, TokenVerifyResponse
from app.utils.security import decode_token
from app.utils.config import settings
from app.utils.logging import get_logger
from slowapi import Limiter
from slowapi.util import get_remote_address

# Initialize logger for tracking verification attempts
logger = get_logger(__name__)
# Create router for the verification endpoint
router = APIRouter(prefix="", tags=["Token Verification Endpoint (Interservice Communication)"])
# Configure rate limiting to prevent brute force attacks
limiter = Limiter(key_func=get_remote_address)

@router.post("/verify", response_model=TokenVerifyResponse)
@limiter.limit(f"{settings.RATE_LIMITS_PRIVATE_ROUTES}/{settings.RATE_LIMITS_PRIVATE_TIME_UNIT}")
async def verify_token(
    request: Request,
    token_data: TokenVerify,
    db: Session = Depends(get_db)
):
    # Log verification request for audit trail
    logger.info("Token verification request received")
    
    # Verify service token to ensure request comes from authorized service
    if token_data.service_token != settings.SERVICE_TOKEN:
        logger.warning("Token verification failed: Invalid service token")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found"
        )
    
    # Look up the user by their token in the database
    user = db.query(User).filter(User.token == token_data.user_token).first()
    if not user:
        logger.warning("Token verification failed: User token not found")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found"
        )
    
    # Decode and verify token authenticity using user's secret
    payload = decode_token(token_data.user_token, user.secret)
    if not payload:
        logger.warning("Token verification failed: Invalid token payload")
        user.token = None
        user.secret = None
        user.iddle_time = None
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found"
        )
    
    # Verify the token belongs to the correct user by checking ID
    if payload.get("id") != user.id:
        logger.warning("Token verification failed: Token ID mismatch")
        user.token = None
        user.secret = None
        user.iddle_time = None
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found"
        )
    
    # Check if the session has expired due to inactivity
    if user.iddle_time:
        current_time = datetime.utcnow()
        idle_delta = current_time - user.iddle_time
        idle_minutes = idle_delta.total_seconds() / 60
        
        if idle_minutes > settings.IDDLE_MINUTES:
            logger.warning(f"Token verification failed: Token expired (idle for {idle_minutes:.2f} minutes)")
            user.token = None
            user.secret = None
            user.iddle_time = None
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired"
            )
    
    # Reset idle timer on successful verification
    user.iddle_time = func.now()
    db.commit()
    
    # Log successful verification for audit purposes
    logger.info(f"Token verified successfully for user ID: {user.id}")
    
    # Return user information to the requesting service
    return TokenVerifyResponse(id=user.id, email=user.email, nickname=user.nickname, role=user.role, lock=user.lock, customer_account=user.customer_account)

# Export the router to be included in the main application
verify_router = router
