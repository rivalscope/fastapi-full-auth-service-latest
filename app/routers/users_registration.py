"""
User Registration Module
========================

Purpose:
--------
This module handles user account creation with proper validation and security measures
as part of a comprehensive authentication system using FastAPI.

Functionality:
-------------
- Creates new user accounts with email, nickname, and password
- Implements form validation and error handling
- Ensures email uniqueness across the system
- Assigns roles based on user registration order (first user becomes admin)
- Secures passwords through hashing

Flow:
-----
1. User submits registration data (email, nickname, password)
2. System validates input and checks for existing email
3. Password is securely hashed
4. User role is determined (admin for first user, regular user otherwise)
5. User record is created in the database
6. Registration confirmation is returned to client

Security:
---------
- Password hashing using bcrypt algorithm
- Rate limiting to prevent brute force attacks
- Email validation to ensure uniqueness
- Role-based access control
- Password strength validation

Dependencies:
------------
- FastAPI: Web framework for building the API
- SQLAlchemy: ORM for database operations
- slowapi: Rate limiting middleware
- bcrypt (via security utils): Password hashing

Usage:
------
This module is imported and included in the main FastAPI application.
Client applications can send POST requests to the registration endpoint
with required user information.

Endpoints:
---------
POST /register: Creates a new user account
  - Request body: UserCreate schema (email, nickname, password, customer_account)
  - Returns: UserOut schema (user details without password)
  - Status codes: 201 Created, 400 Bad Request, 429 Too Many Requests
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from sqlalchemy.sql import func

from app.utils.db import get_db
from app.models.users_table import User
from app.schemas.user import UserCreate, UserOut
from app.utils.security import get_password_hash
from app.utils.config import settings
from app.utils.logging import get_logger, mask_password
from app.utils.password_validation import validate_password_strength
from slowapi import Limiter
from slowapi.util import get_remote_address

# Initialize logger for this module
logger = get_logger(__name__)

# Create API router with appropriate tags for documentation
router = APIRouter(prefix="", tags=["Users Registration Endpoint"])

# Set up rate limiting to prevent brute force attacks
limiter = Limiter(key_func=get_remote_address)

@router.post(
    "/register", 
    response_model=UserOut, 
    status_code=status.HTTP_201_CREATED,
    openapi_extra={"security": []}  # Public endpoint - no auth required
)
@limiter.limit(f"{settings.RATE_LIMITS_PUBLIC_ROUTES}/{settings.RATE_LIMITS_PUBLIC_TIME_UNIT}")
async def register(
    request: Request,
    user_data: UserCreate,
    db: Session = Depends(get_db)
):
    # Log registration attempt for audit trail
    logger.info(f"Registration attempt for email: {user_data.email}")
    
    # Validate mandatory fields
    if not user_data.email:
        logger.warning("Registration failed: Missing email")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is required"
        )
    
    if not user_data.password:
        logger.warning("Registration failed: Missing password")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password is required"
        )
    
    # Validate password strength using the utility function
    password_validation = validate_password_strength(user_data.password)
    if not password_validation["valid"]:
        logger.warning(f"Registration failed: Weak password for {user_data.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=password_validation["message"]
        )
    
    if not user_data.nickname:
        logger.warning("Registration failed: Missing nickname")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nickname is required"
        )
    
    if not user_data.passphrase:
        logger.warning(f"Registration failed: Missing passphrase for {user_data.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passphrase is required"
        )
    
    # Check if email already exists to prevent duplicate accounts
    db_user = db.query(User).filter(User.email == user_data.email).first()
    if db_user:
        logger.warning(f"Registration failed: Email {user_data.email} already registered")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Check if nickname already exists to prevent duplicate nicknames
    nickname_exists = db.query(User).filter(User.nickname == user_data.nickname).first()
    if nickname_exists:
        logger.warning(f"Registration failed: Nickname {user_data.nickname} already taken")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nickname already taken"
        )
    
    # Hash the password for secure storage
    hashed_password = get_password_hash(user_data.password)
    logger.debug(f"Password hashed for new user: {user_data.email}, password: {mask_password(user_data.password)}")
    
    # Determine if this is the first user (who gets admin rights)
    is_first_user = db.query(User).count() == 0
    role = "admin" if is_first_user else "user"
    
    # Create new user object with required attributes
    new_user = User(
        nickname=user_data.nickname,
        email=user_data.email,
        password=hashed_password,
        passphrase=user_data.passphrase,  # Add the passphrase field
        role=role,
        customer_account=user_data.customer_account,
        iddle_time=func.now(),  # Track initial timestamp
        secret=None,  # Authentication secret is not set during registration
        token=None,   # Token is generated during login, not registration
        lock=False    # Account starts in unlocked state
    )
    
    # Save the new user to the database
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Log successful registration
    logger.info(f"User registered successfully: {new_user.email} with role {new_user.role}")
    
    # Return user data (password field excluded by UserOut schema)
    return new_user

# Export router to be included in the main application
registration_router = router
