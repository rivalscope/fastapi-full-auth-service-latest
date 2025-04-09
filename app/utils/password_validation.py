"""
Password Validation Utility
===========================

Purpose:
--------
This module provides functions for validating password strength according to
security best practices.

Functions:
---------
- validate_password_strength: Checks password against multiple security criteria
"""

import re
from app.utils.logging import get_logger

# Initialize logger for this module
logger = get_logger(__name__)

def validate_password_strength(password: str) -> dict:
    """
    Validates password strength based on multiple criteria.
    
    Args:
        password (str): The password to validate
        
    Returns:
        dict: Contains 'valid' status (bool) and 'message' explaining any failure.
    """
    # Check for minimum length
    if len(password) < 8:
        return {"valid": False, "message": "Password must be at least 8 characters long, and must contain at least one off the following: one uppercase letter, one lowercase letter, one digit, and one special character"}
    
    # Check for uppercase letters
    if not re.search(r'[A-Z]', password):
        return {"valid": False, "message": "Password must be at least 8 characters long, and must contain at least one off the following: one uppercase letter, one lowercase letter, one digit, and one special character"}
    
    # Check for lowercase letters
    if not re.search(r'[a-z]', password):
        return {"valid": False, "message": "Password must be at least 8 characters long, and must contain at least one off the following: one uppercase letter, one lowercase letter, one digit, and one special character"}
    
    # Check for digits
    if not re.search(r'\d', password):
        return {"valid": False, "message": "Password must be at least 8 characters long, and must contain at least one off the following: one uppercase letter, one lowercase letter, one digit, and one special character"}
    
    # Check for special characters
    if not re.search(r'[!@#$%^&*(),.?":{}|<>+]', password):
        return {"valid": False, "message": "Password must be at least 8 characters long, and must contain at least one off the following: one uppercase letter, one lowercase letter, one digit, and one special character"}
    
    return {"valid": True, "message": "Password meets strength requirements"}
