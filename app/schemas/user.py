"""
# User Schema Module

## Purpose
This module defines Pydantic models for user data validation, serialization, and deserialization
in the routes modules of the application.

## Functionality
- Defines base user data structure and validation rules
- Provides schemas for user registration, authentication, and data management
- Implements data validation for security requirements (e.g., password strength)
- Supports different user data representations for various API operations

## Flow
1. API endpoints receive user data as JSON
2. Data is parsed and validated using appropriate schema models
3. Validated data is passed to services for processing
4. Database models are converted to response schemas when returning data

## Security
- Enforces password strength requirements (minimum 8 characters)
- Uses Pydantic's validation system to prevent malformed data
- Implements strict schema models to prevent over-posting attacks
- Separates internal and external user representations to prevent data leakage

## Dependencies
- pydantic: For data validation and settings management
- typing: For type hints
- datetime: For handling timestamp fields

## Usage
Import and use these schemas in route handlers for request validation:
```python
from app.schemas.user import UserCreate, UserLogin, UserOut
```

Routes typically use these schemas as:
- Request models (e.g., UserCreate, UserLogin)
- Response models (e.g., UserOut)
- Internal data models (e.g., UserInDB)
"""

from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional
from datetime import datetime

# Base user model with common user attributes
class UserBase(BaseModel):
    nickname: str
    email: EmailStr
    customer_account: Optional[str] = "none"
    passphrase: Optional[str] = None

    


# Schema for user registration with password validation
class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    
    @field_validator('password')
    @classmethod
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v
    
    model_config = {
        "extra": "forbid"
    }

# Schema for user login credentials
class UserLogin(BaseModel):
    email: EmailStr
    password: str
    
# Schema for retrieving or updating account details
class UserAccountDetails(BaseModel):
    nickname: Optional[str] = None
    email: Optional[EmailStr] = None
    customer_account: Optional[str] = None
    passphrase: Optional[str] = None

# Schema for updating user information
class UserUpdate(BaseModel):
    nickname: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    customer_account: Optional[str] = None
    passphrase: Optional[str] = None
    
    model_config = {
        "extra": "forbid"
    }

# Schema for admin updating user information with additional fields
class UserAdminUpdate(UserUpdate):
    role: Optional[str] = None
    lock: Optional[bool] = None
    nickname: Optional[str] = None
    email: Optional[EmailStr] = None
    password: Optional[str] = None
    customer_account: Optional[str] = None
    passphrase: Optional[str] = None

# Schema for user password recovery
class UserPasswordRecovery(BaseModel):
    email: EmailStr
    passphrase: str
    new_password: str = Field(..., min_length=8)
    
    @field_validator('new_password')
    @classmethod
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v

# Internal schema for user data stored in the database
class UserInDB(UserBase):
    id: int
    role: str
    lock: bool
    iddle_time: Optional[datetime] = None
    
    model_config = {
        "from_attributes": True
    }

# Schema for user data returned in API responses
class UserOut(BaseModel):
    id: int
    nickname: str
    email: EmailStr

    
    model_config = {
        "from_attributes": True
    }
