"""
Purpose:
This module provides an API endpoint for securely recovering user accounts by resetting their passwords.

Functionality:
- Implements a POST endpoint for password recovery.
- Verifies user identity using email and nickname.
- Updates the password securely using hashing.
- Invalidates existing authentication tokens upon password reset.

Flow:
1. User submits email, nickname, and new password.
2. System verifies the email and nickname match a user record.
3. If matched, the password is updated with a hashed version.
4. Existing tokens are invalidated for security.
5. A success response is returned.

Security:
- Requires both email and nickname for verification.
- Uses hashed passwords for secure storage.
- Invalidates tokens to prevent unauthorized access after password reset.
- Logs all recovery attempts for auditing.

Dependencies:
- FastAPI for routing and dependency injection.
- SQLAlchemy for database operations.
- Custom utilities for password hashing and logging.

Usage:
Include this router in the main FastAPI application to enable password recovery functionality.

Endpoints:
- POST /recovery: Resets a user's password after verifying email and nickname.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.utils.db import get_db
from app.models.users_table import User
from app.schemas.user import UserPasswordRecovery
from app.utils.security import get_password_hash
from app.utils.logging import get_logger
from app.utils.password_validation import validate_password_strength
import logging

# Initialize logger for this module
logger = logging.getLogger(__name__)

# Create a FastAPI router with a prefix and tags for organization
router = APIRouter(prefix="/recovery", tags=["Password Recovery"])

# Define the password recovery endpoint
@router.post(
    "", 
    status_code=status.HTTP_200_OK,
    openapi_extra={"security": []}  # Public endpoint - no auth required
)
async def recover_password(
    recovery_data: UserPasswordRecovery,  # Input data containing email, nickname, and new password
    db: Session = Depends(get_db)  # Inject database session dependency
):
    try:
        # Log the password recovery attempt
        logger.info(f"Password recovery attempt for email: {recovery_data.email}")
        
        # Query the database for a user matching the provided email and nickname
        user = db.query(User).filter(
            User.email == recovery_data.email,
            User.passphrase == recovery_data.passphrase
        ).first()
        
        # If no user matches, raise an HTTP 400 error
        if not user:
            logger.warning(f"Password recovery failed: Email or passphrase do not match for {recovery_data.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Entered details do not match"
            )
        
        # Validate the new password strength
        password_validation = validate_password_strength(recovery_data.new_password)
        if not password_validation["valid"]:
            logger.warning(f"Password recovery failed: Weak password for email {recovery_data.email}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=password_validation["message"]
            )
        
        # Hash the new password for secure storage
        hashed_password = get_password_hash(recovery_data.new_password)
        logger.debug(f"Password hashed for user: {recovery_data.email}")
        
        # Update the user's password and invalidate existing tokens
        user.password = hashed_password
        user.token = None
        user.secret = None
        
        # Commit the changes to the database
        db.commit()
        
        # Log the successful password recovery
        logger.info(f"Password recovery successful for email: {recovery_data.email}")
        
        # Return a success message
        return {"message": "Password changed successfully"}
        
    except HTTPException:
        # Re-raise HTTP exceptions to preserve their status and details
        raise
    except Exception as e:
        # Log unexpected errors and raise a generic HTTP 500 error
        logger.error(f"Error in password recovery: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during password recovery"
        )

# Export router for inclusion in the main application
recovery_router = router