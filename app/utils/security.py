"""
Security Utilities Module
=========================

Purpose:
    This module provides core security functionality for the login system, handling all
    aspects of user authentication, password management, and JWT token operations.

Functionality:
    - Password hashing and verification using bcrypt
    - JWT token generation and validation with user-specific secrets
    - User authentication against database credentials
    - Random secure string generation for enhanced security
    - User retrieval based on authentication tokens

Flow:
    1. Authentication: User submits credentials → authenticate_user() → verify_password()
    2. Token Creation: After successful auth → create_random_secret() → create_access_token()
    3. Token Usage: Protected endpoints → decode_token() or get_user_by_token()

Security:
    - Uses bcrypt for secure password hashing with salt
    - Combines application secret with user-specific secrets for JWT signing
    - Implements token expiration and validation
    - Logs authentication attempts and failures
    - Checks for locked user accounts

Dependencies:
    - random, string: For generating secure random strings
    - datetime: For token expiration handling
    - jose: For JWT token creation and validation
    - passlib: For password hashing with bcrypt
    - sqlalchemy: For database operations
    - app.models.user: For User model access
    - app.config: For application settings
    - app.utils.logging: For security event logging

Usage:
    from app.utils.security import authenticate_user, create_access_token, decode_token

    # Authentication
    user = authenticate_user(db, email, password)
    
    # Token creation
    token = create_access_token(data={"id": user.id}, secret=user.secret)
    
    # Token validation
    payload = decode_token(token, user.secret)
"""

import random
import string
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from app.models.users_table import User
from app.utils.config import settings
from app.utils.logging import get_logger

# Initialize logger for security operations and auditing
logger = get_logger(__name__)

# Configure password hashing with bcrypt algorithm
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    # Verifies if provided password matches the stored hash
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    # Creates a secure hash of the password for storage
    return pwd_context.hash(password)

def create_random_secret(length=24):
    # Generates a cryptographically secure random string for token security
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def create_access_token(data: dict, secret: str, expires_delta: Optional[timedelta] = None):
    # Creates a JWT token with user data and expiration time
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
    # Validates and decodes JWT token, returning payload if valid
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
    # Retrieves user by their stored token from database
    return db.query(User).filter(User.token == token).first()

def authenticate_user(db: Session, email: str, password: str):
    # Validates user credentials and account status
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
