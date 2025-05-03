"""
Security Utilities Module
=========================

Purpose:
    This module provides core security functionality for the login system, handling all
    aspects of user authentication, password management, and JWT token operations.

Functionality:
    - Password hashing and verification using modern cryptography library
    - JWT token generation and validation with user-specific secrets
    - User authentication against database credentials
    - Random secure string generation for enhanced security
    - User retrieval based on authentication tokens
    - Bearer token extraction and validation
    - Service token validation

Flow:
    1. Authentication: User submits credentials → authenticate_user() → verify_password()
    2. Token Creation: After successful auth → create_random_secret() → create_access_token()
    3. Token Usage: Protected endpoints → decode_token() or get_user_by_token()
    4. Bearer Authentication: extract_token_from_header() → get_user_by_token()

Security:
    - Uses PBKDF2-HMAC-SHA256 for secure password hashing with salt
    - Combines application secret with user-specific secrets for JWT signing
    - Implements token expiration and validation
    - Logs authentication attempts and failures
    - Checks for locked user accounts
    - Standard Bearer HTTP authentication
    - Service-to-service authentication via API key

Dependencies:
    - random, string: For generating secure random strings
    - datetime: For token expiration handling
    - jose: For JWT token creation and validation
    - cryptography: Modern cryptographic functions for password hashing
    - sqlalchemy: For database operations
    - app.models.user: For User model access
    - app.config: For application settings
    - app.utils.logging: For security event logging
    - fastapi.security: For HTTP Bearer and API key security schemes

Usage:
    from app.utils.security import authenticate_user, create_access_token, decode_token
    from app.utils.security import oauth2_scheme, api_key_header, extract_token_from_header

    # Authentication
    user = authenticate_user(db, email, password)
    
    # Token creation
    token = create_access_token(data={"id": user.id}, secret=user.secret)
    
    # Token validation
    payload = decode_token(token, user.secret)
    
    # Bearer token dependency
    @app.get("/protected")
    async def protected_route(token: str = Depends(oauth2_scheme)):
        # Use token
"""

import random
import string
import secrets
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from app.models.users_table import User
from app.utils.config import settings
from app.utils.logging import get_logger
from app.utils.password import verify_password, get_password_hash
from fastapi import Security, HTTPException, status
from fastapi.security import HTTPBearer, APIKeyHeader

# Initialize logger for security operations and auditing
logger = get_logger(__name__)

# Define security schemes for OpenAPI docs
oauth2_scheme = HTTPBearer(
    scheme_name="userAuth",
    description="Short-lived opaque key the browser holds",
    bearerFormat="OPAQUE",
    auto_error=False
)

api_key_header = APIKeyHeader(
    name="X-Service-Token", 
    scheme_name="serviceAuth",
    description="Internal service secret",
    auto_error=False
)

def extract_token_from_header(authorization: Optional[str] = None):
    """
    Extracts token from the Authorization header
    
    Args:
        authorization: The Authorization header value (Bearer token)
        
    Returns:
        The token string if valid, None otherwise
    """
    if not authorization:
        return None
        
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return None
        
    return token

def verify_service_token(service_token: str):
    """
    Validates the service token against the configured value
    
    Args:
        service_token: The service token to validate
        
    Returns:
        True if valid, False otherwise
    """
    return service_token == settings.SERVICE_TOKEN

def create_random_secret(length=24):
    """
    Generates a cryptographically secure random string for token security
    
    Args:
        length: Length of the random string to generate
        
    Returns:
        Secure random string of specified length
    """
    # Use secrets module for cryptographically secure random generation
    return secrets.token_urlsafe(length)

def create_access_token(data: dict, secret: str, expires_delta: Optional[timedelta] = None):
    """
    Creates a JWT token with user data and expiration time
    
    Args:
        data: Dictionary containing data to encode in the token
        secret: User-specific secret for token signing
        expires_delta: Optional custom expiration time
        
    Returns:
        JWT token string
    """
    to_encode = data.copy()
    
    # Set token expiration time based on parameter or default setting
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Add expiration claim to token payload
    to_encode.update({"exp": expire})
    
    # Create token with combined app and user-specific secrets
    combined_secret = f"{settings.SECRET_KEY}{secret}"
    encoded_jwt = jwt.encode(to_encode, combined_secret, algorithm=settings.ALGORITHM)
    
    # Log token creation for audit trail
    logger.debug(f"Created token for user with ID: {data.get('id')}")
    return encoded_jwt

def decode_token(token: str, secret: str):
    """
    Validates and decodes JWT token, returning payload if valid
    
    Args:
        token: JWT token string to validate and decode
        secret: User-specific secret used in token signing
        
    Returns:
        Token payload dictionary if valid, None otherwise
    """
    try:
        # Recreate the combined secret used for token signing
        combined_secret = f"{settings.SECRET_KEY}{secret}"
        payload = jwt.decode(token, combined_secret, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError as e:
        # Log failed validation attempts for security monitoring
        logger.warning(f"Invalid token: {str(e)}")
        return None

def get_user_by_token(db: Session, token: str):
    """
    Retrieves user by their stored token from database
    
    Args:
        db: Database session
        token: Token string to look up
        
    Returns:
        User object if found, None otherwise
    """
    return db.query(User).filter(User.token == token).first()

def authenticate_user(db: Session, email: str, password: str):
    """
    Validates user credentials and account status
    
    Args:
        db: Database session
        email: User's email address
        password: Plain text password to verify
        
    Returns:
        User object if authentication successful, None otherwise
    """
    user = db.query(User).filter(User.email == email).first()
    
    # Check if user exists in database
    if not user:
        logger.warning(f"Authentication failed: No user found with email {email}")
        return None
    
    # Check if user account is locked
    if user.lock:
        logger.warning(f"Authentication failed: User {email} is locked")
        return None
    
    # Verify password matches stored hash
    if not verify_password(password, user.password):
        logger.warning(f"Authentication failed: Invalid password for {email}")
        return None
    
    # Log successful authentication
    logger.info(f"User {email} authenticated successfully")
    return user
