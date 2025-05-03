"""
# User Authentication Module
===============================

## Purpose
This module manages user authentication in the application, providing secure login and logout functionality
through a REST API. It handles authentication tokens and session management for users.

## Functionality
- User login with email/password validation
- JWT token generation with unique secret per session
- Session tracking with idle time monitoring
- Secure logout with token invalidation
- Rate limiting to prevent brute force attacks
- Comprehensive activity logging

## Flow
1. Login: User submits credentials → validation → token generation → session creation
2. Session: Token stored with unique secret and idle time tracked
3. Logout: Token validated → session terminated → user state updated

## Security
- Per-session unique JWT secrets
- Token invalidation on logout
- Rate limiting protection against brute force
- Password never stored or logged in plaintext
- Activity logging for security audit trail
- Standard HTTP Bearer authentication

## Dependencies
- FastAPI: Web framework for API endpoints
- SQLAlchemy: Database ORM for user data
- JWT: Token-based authentication
- SlowAPI: Rate limiting implementation

## Usage
Import and include this router in your FastAPI application:
```python
from app.routers.users_auth import auth_router
app.include_router(auth_router)
```

## Endpoints
- POST /login: Authenticate user and generate token
- POST /logout: Invalidate user session
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Security
from sqlalchemy.orm import Session
from sqlalchemy.sql import func

# Database and model imports
from app.utils.db import get_db
from app.models.users_table import User
from app.schemas.user import UserLogin
from app.schemas.token import LoginResponse

# Security utilities
from app.utils.security import (
    authenticate_user, create_access_token, 
    create_random_secret, oauth2_scheme, extract_token_from_header
)

# Configuration and logging
from app.utils.config import settings
from app.utils.logging import get_logger

# Rate limiting
from slowapi import Limiter
from slowapi.util import get_remote_address

# Initialize logger for authentication events
logger = get_logger(__name__)

# Create API router with authentication endpoints tag
router = APIRouter(prefix="", tags=["Authentication Endpoints Login / logout"])

# Configure rate limiter using client IP address
limiter = Limiter(key_func=get_remote_address)

@router.post(
    "/login", 
    response_model=LoginResponse,
    openapi_extra={"security": []}
)
@limiter.limit(f"{settings.RATE_LIMITS_PUBLIC_ROUTES}/{settings.RATE_LIMITS_PUBLIC_TIME_UNIT}")
async def login(
    request: Request,
    user_data: UserLogin,
    db: Session = Depends(get_db)
):
    # Log login attempt with email for audit trail
    logger.info(f"Login attempt for email: {user_data.email}")
    
    # Authenticate user credentials against database
    user = authenticate_user(db, user_data.email, user_data.password)
    if not user:
        # Log and respond to failed authentication
        logger.warning(f"Login failed: Invalid credentials for {user_data.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Generate unique secret for this session's JWT
    secret = create_random_secret()
    
    # Prepare user data for token and create JWT
    token_data = {"id": user.id, "nickname": user.nickname, "role": user.role}
    access_token = create_access_token(token_data, secret)
    
    # Update user record with new session information
    user.token = access_token
    user.secret = secret
    user.iddle_time = func.now()
    user.is_logged_in = True
    
    # Save changes to database
    db.commit()
    
    # Log successful authentication
    logger.info(f"User logged in successfully: {user.email}")
    
    # Return token and user information
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user": user
    }

@router.post("/logout")
@limiter.limit(f"{settings.RATE_LIMITS_PUBLIC_ROUTES}/{settings.RATE_LIMITS_PUBLIC_TIME_UNIT}")
async def logout(
    request: Request,
    auth = Security(oauth2_scheme),
    db: Session = Depends(get_db)
):
    # Log logout attempt
    logger.info("Logout attempt")
    
    # Get token directly from the credentials object
    if not auth:
        # Log and respond to missing token
        logger.warning("Logout failed: No token provided")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Use the token value directly from the credentials
    token = auth.credentials
    
    # Find user by token to validate session
    user = db.query(User).filter(User.token == token).first()
    if not user:
        # Log and respond to invalid token
        logger.warning("Logout failed: Invalid token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Clear user session data to invalidate token
    user.token = None
    user.secret = None
    user.iddle_time = None
    user.is_logged_in = False
    
    # Save changes to database
    db.commit()
    
    # Log successful logout
    logger.info(f"User logged out successfully: {user.email}")
    
    # Return success message
    return {"detail": "Logged out successfully"}

# Export router for application inclusion
auth_router = router
