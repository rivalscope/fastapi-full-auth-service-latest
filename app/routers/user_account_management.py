"""
User Account Management API
===========================

Purpose:
    Provides API endpoints for users to manage their own account data within the application.

Functionality:
    - Retrieve user account information
    - Update user profile information (nickname, email, password, customer status)  
    - Delete user accounts

Flow:
    1. Each endpoint authenticates the user via Bearer token authentication
    2. Requested operations are performed on the authenticated user's data only
    3. Database is updated with changes
    4. Appropriate responses are returned to the client

Security:
    - Bearer token authentication required for all operations
    - Password hashing for secure storage
    - Email uniqueness validation
    - Operations restricted to the account owner only
    - Sensitive operations are logged for audit purposes
    - Password strength validation

Dependencies:
    - FastAPI framework for API routing
    - SQLAlchemy for database operations
    - Custom security utilities for authentication
    - Logging utilities for operation tracking

Usage:
    These endpoints are designed to be called by the frontend application after
    a user has successfully logged in and received an authentication token.

Endpoints:
    - GET /my_account/: Retrieve user account details
    - PUT /my_account/: Update user account information
    - DELETE /my_account/delete: Delete user account permanently
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Security
from sqlalchemy.orm import Session
from app.utils.db import get_db
from app.models.users_table import User
from app.schemas.user import UserUpdate, UserAccountDetails
from app.utils.security import get_password_hash, get_user_by_token, oauth2_scheme, extract_token_from_header
from app.utils.logging import get_logger, mask_password
from app.utils.password_validation import validate_password_strength

# Initialize logger for tracking operations
logger = get_logger(__name__)

# Create router with API path prefix and documentation tag
router = APIRouter(prefix="/my_account", tags=["User Accounts management"])

@router.get("/", response_model=UserAccountDetails)
async def get_account(
    auth = Security(oauth2_scheme),
    db: Session = Depends(get_db)
):
    # Get token directly from the credentials object
    if not auth:
        # Return unauthorized error if no token provided
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Use the token value directly from the credentials
    token = auth.credentials
    
    # Authenticate user with provided token
    user = get_user_by_token(db, token)
    if not user:
        # Return unauthorized error if token is invalid
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Return the authenticated user's account information
    return user

@router.put("/")
async def update_account(
    user_data: UserUpdate,
    request: Request,
    auth = Security(oauth2_scheme),
    db: Session = Depends(get_db)
):
    # Get token directly from the credentials object
    if not auth:
        # Return unauthorized error if no token provided
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Use the token value directly from the credentials
    token = auth.credentials
    
    # Authenticate user with provided token
    user = get_user_by_token(db, token)
    if not user:
        # Return unauthorized error if token is invalid
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Extract fields actually provided in the request
    update_data = await request.json()
    
    # Update nickname if provided
    if "nickname" in update_data and user_data.nickname is not None:
        user.nickname = user_data.nickname
    
    # Update email if provided and different from current email
    if "email" in update_data and user_data.email is not None and user_data.email != user.email:
        # Check if email is already used by another account
        existing_user = db.query(User).filter(User.email == user_data.email).first()
        if existing_user:
            # Return error if email is already registered
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        user.email = user_data.email
    
    # Update password if provided
    if "password" in update_data and user_data.password is not None:
        # Validate password strength
        password_validation = validate_password_strength(user_data.password)
        if not password_validation["valid"]:
            logger.warning(f"Account update failed: Weak password for user ID {user.id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=password_validation["message"]
            )
        user.password = get_password_hash(user_data.password)
    
    # Update customer account status if provided
    if "customer_account" in update_data and user_data.customer_account is not None:
        user.customer_account = user_data.customer_account
   
    # Update passphrase status if provided  
    if "passphrase" in update_data and user_data.passphrase is not None:
        user.passphrase = user_data.passphrase
    
    # Save changes to database
    db.commit()
    db.refresh(user)
    
    # Return success message
    return {"message": "Account details updated successfully"}

@router.delete("/delete")
async def delete_account(
    auth = Security(oauth2_scheme),
    db: Session = Depends(get_db)
):
    # Get token directly from the credentials object
    if not auth:
        # Return unauthorized error if no token provided
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Use the token value directly from the credentials
    token = auth.credentials
    
    # Authenticate user with provided token
    user = get_user_by_token(db, token)
    if not user:
        # Return unauthorized error if token is invalid
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Store user ID for logging after deletion
    user_id = user.id
    
    # Remove user from database
    db.delete(user)
    db.commit()
    
    # Log successful deletion for audit purposes
    logger.info(f"Account deleted successfully for user ID: {user_id}")
    
    # Return success message
    return {"detail": "Account deleted successfully"}

# Export router for inclusion in main application
accounts_router = router
