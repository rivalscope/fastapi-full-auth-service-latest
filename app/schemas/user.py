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

from pydantic import BaseModel, EmailStr, Field, field_validator, computed_field
from typing import Optional
from datetime import datetime, timedelta

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
    is_logged_in: bool = False
    
    @computed_field
    @property
    def idle_duration(self) -> Optional[str]:
        """Returns idle time in a human-readable format (minutes and seconds)"""
        if not self.iddle_time:
            return None
            
        now = datetime.utcnow()
        idle_duration = now - self.iddle_time
        
        # Calculate minutes and seconds
        total_seconds = int(idle_duration.total_seconds())
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        
        # Format the idle duration as "X min Y sec"
        if minutes > 0:
            return f"{minutes} min {seconds} sec"
        else:
            return f"{seconds} sec"
    
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
