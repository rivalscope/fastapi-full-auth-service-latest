"""
# ADMIN ACCOUNTS MANAGEMENT MODULE

## Purpose:
This module provides API endpoints for administrators to manage user accounts in the system.
It enables secure, role-based administrative access to user account operations.

## Functionality:
- List all users in the system with pagination support
- Retrieve detailed information about specific users
- Create new user accounts with configurable permissions
- Update existing user information including emails, passwords, and roles
- Delete user accounts from the system
- Lock/unlock user accounts for security purposes

## Flow:
1. Admin authentication verification through Bearer token validation
2. Role-based access control ensuring only admin users can access endpoints
3. Database operations via SQLAlchemy ORM
4. Comprehensive logging for audit and security monitoring
5. Secure password handling with hashing

## Security:
- All endpoints require valid authentication token via Bearer header
- Admin role verification before allowing sensitive operations
- Password hashing for secure storage
- Account locking capability for security incidents
- Extensive logging for security monitoring and auditing
- Protection against admin self-deletion

## Rate Limiting:
- Admin endpoints in this module MUST NOT be rate limited
- Administrative operations require unrestricted access for system management
- These endpoints are already protected by authentication and role-based access control

## Dependencies:
- FastAPI framework for API routing
- SQLAlchemy for database operations
- Pydantic for data validation and serialization
- Custom security utilities for authentication and authorization
- Custom logging utilities for audit trails

## Usage:
Import and include this router in a FastAPI application:
```python
from app.routers.admin_accounts_management import auth_router as admin_router
app.include_router(admin_router)
```

## Endpoints:
- GET /accounts_management/ - List all users with pagination
- GET /accounts_management/{user_id} - Get details for a specific user
- POST /accounts_management/ - Create a new user
- PUT /accounts_management/{user_id} - Update user information
- DELETE /accounts_management/{user_id} - Delete a user
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Security
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from app.utils.db import get_db
from app.models.users_table import User
from app.schemas.user import UserCreate, UserAdminUpdate, UserInDB
from app.utils.security import get_password_hash, get_user_by_token, oauth2_scheme, extract_token_from_header, is_user_active
from app.utils.logging import get_logger, mask_password
from app.utils.password_validation import validate_password_strength

# Initialize logger for security and operation tracking
logger = get_logger(__name__)

# Configure FastAPI router with prefix and metadata
# NOTE: All endpoints in this router MUST NOT be rate limited.
# Administrative functions require unthrottled access for system management.
router = APIRouter(
    prefix="/accounts_management",
    tags=["Admin Accounts management"],
    responses={404: {"description": "Not found"}},
)

async def get_current_admin_user(
    auth = Security(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    # Get token directly from the credentials object
    if not auth:
        logger.warning("Admin access attempt failed: No token provided")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Use the token value directly from the credentials
    token = auth.credentials
    
    # Authenticate user based on token and verify admin privileges
    user = get_user_by_token(db, token)
    if not user:
        logger.warning("Admin access attempt failed: Invalid token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Ensure user has admin role before granting access
    if user.role != "admin":
        logger.warning(f"Unauthorized admin access attempt by user ID: {user.id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Admin role required.",
        )
    return user

@router.get("/", response_model=List[UserInDB])
async def list_all_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
):
    # Retrieve paginated list of all users in the system
    logger.info(f"Admin {current_user.id} requested user list. Skip: {skip}, Limit: {limit}")
    users = db.query(User).offset(skip).limit(limit).all()
    
    # Check and update active status for each user based on idle time
    for user in users:
        is_user_active(user, update_status=True, db=db)
    
    logger.debug(f"Returning {len(users)} users to admin {current_user.id}")
    return users

@router.get("/{user_id}", response_model=UserInDB)
async def get_user_details(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
):
    # Retrieve details for a specific user by ID
    logger.info(f"Admin {current_user.id} requested details for user ID: {user_id}")
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        logger.warning(f"Admin {current_user.id} attempted to access non-existent user ID: {user_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id {user_id} not found",
        )
    
    # Check if user is active based on idle time
    is_user_active(user, update_status=True, db=db)
    
    logger.debug(f"Returning user details for ID: {user_id} to admin {current_user.id}")
    return user

@router.post("/", response_model=UserInDB, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
):
    # Create a new user account with admin-provided details
    logger.info(f"Admin {current_user.id} attempting to create new user with email: {user_data.email}")
    
    # Validate mandatory fields
    required_fields = ["nickname", "email", "password", "passphrase"]
    missing_fields = [field for field in required_fields if not getattr(user_data, field, None)]
    
    if missing_fields:
        missing_fields_str = ", ".join(missing_fields)
        logger.warning(f"Admin {current_user.id} attempted to create user with missing fields: {missing_fields_str}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Required fields missing",
                "missing_fields": missing_fields,
                "error": f"The following fields are required: {missing_fields_str}"
            }
        )
    
    # Check if user with this email already exists
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        logger.warning(f"Admin {current_user.id} attempted to create user with existing email: {user_data.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists",
        )
    
    # Validate password strength
    password_validation = validate_password_strength(user_data.password)
    if not password_validation["valid"]:
        logger.warning(f"Admin {current_user.id} attempted to create user with weak password for {user_data.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=password_validation["message"]
        )
    
    # Hash password for secure storage
    logger.debug(f"Admin {current_user.id} creating user with password: {mask_password(user_data.password)}")
    hashed_password = get_password_hash(user_data.password)
    
    # Create new user object with default settings
    new_user = User(
        nickname=user_data.nickname,
        email=user_data.email,
        password=hashed_password,
        role="user",
        customer_account=user_data.customer_account,
        passphrase=user_data.passphrase,
        iddle_time=func.now(),
        secret=None,
        token=None,
        lock=False,
        is_logged_in=False
    )
    
    # Save user to database and return the created user
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    logger.info(f"Admin {current_user.id} successfully created new user with ID: {new_user.id}")
    return new_user

@router.put("/{user_id}")
async def update_user(
    user_id: int,
    user_update: UserAdminUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
):
    # Update an existing user's information based on provided fields
    logger.info(f"Admin {current_user.id} attempting to update user ID: {user_id}")
    
    # Extract only the fields that were provided in the request
    update_data = user_update.dict(exclude_unset=True)
    logger.debug(f"Fields included in update request: {list(update_data.keys())}")
    
    # Convert empty strings to None to support field clearing
    for field, value in update_data.items():
        if value == "":
            setattr(user_update, field, None)
            logger.debug(f"Converting empty string to None for field '{field}'")
    
    # Verify user exists before attempting update
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        logger.warning(f"Admin {current_user.id} attempted to update non-existent user ID: {user_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id {user_id} not found",
        )
    
    # Update user fields if they were included in the request
    if "nickname" in update_data and user_update.nickname is not None:
        logger.debug(f"Admin {current_user.id} updating nickname for user {user_id} to: {user_update.nickname}")
        user.nickname = user_update.nickname
    if "email" in update_data and user_update.email is not None:
        logger.debug(f"Admin {current_user.id} updating email for user {user_id} to: {user_update.email}")
        user.email = user_update.email
    if "password" in update_data and user_update.password is not None:
        # Validate password strength
        password_validation = validate_password_strength(user_update.password)
        if not password_validation["valid"]:
            logger.warning(f"Admin {current_user.id} attempted to update user {user_id} with weak password")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=password_validation["message"]
            )
        logger.debug(f"Admin {current_user.id} updating password for user {user_id}: {mask_password(user_update.password)}")
        user.hashed_password = get_password_hash(user_update.password)
    if "customer_account" in update_data and user_update.customer_account is not None:
        logger.debug(f"Admin {current_user.id} updating customer account for user {user_id} to: {user_update.customer_account}")
        user.customer_account = user_update.customer_account  
    if "passphrase" in update_data and user_update.passphrase is not None:
        logger.debug(f"Admin {current_user.id} updating passphrase for user {user_id} to: {user_update.passphrase}")
        user.passphrase = user_update.passphrase    
    if "role" in update_data and user_update.role is not None:
        logger.info(f"Admin {current_user.id} changing role for user {user_id} to: {user_update.role}")
        user.role = user_update.role
    if "lock" in update_data and user_update.lock is not None:
        was_locked = user.lock
        user.lock = user_update.lock
        
        # Special handling when locking an account
        if user_update.lock and not was_locked:
            logger.info(f"Admin {current_user.id} locked account for user {user_id}")
            pass
    
    # Save changes to database
    db.commit()
    logger.info(f"Admin {current_user.id} successfully updated user ID: {user_id}")
    return {"message": f"User details successfully updated for user {user_id}"}

@router.delete("/{user_id}", status_code=status.HTTP_200_OK)
async def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
):
    # Delete a user account from the system
    logger.info(f"Admin {current_user.id} attempting to delete user ID: {user_id}")
    
    # Verify user exists before attempting deletion
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        logger.warning(f"Admin {current_user.id} attempted to delete non-existent user ID: {user_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with id {user_id} not found",
        )
    
    # Prevent admins from deleting their own accounts
    if user.id == current_user.id:
        logger.warning(f"Admin {current_user.id} attempted to delete their own account")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot delete their own accounts",
        )
    
    # Revoke user credentials before deletion
    logger.debug(f"Revoking credentials for user {user_id} before deletion")
    
    # Remove user from database
    db.delete(user)
    db.commit()
    logger.info(f"Admin {current_user.id} successfully deleted user ID: {user_id}")
    return {"message": f"User {user_id} has been successfully deleted"}

# Router export for inclusion in the main application
admin_router = router

