"""
# Token Schemas Module

## Purpose
Defines Pydantic schema models for JWT (JSON Web Token) token handling in the authentication system.
These schemas provide structured data validation and serialization for token-related operations.

## Functionality
- Defines structure for authentication tokens
- Specifies payload data contained in tokens
- Provides schemas for token verification requests and responses
- Structures login response data combining tokens and user information

## Flow
1. User authentication generates Token/LoginResponse objects
2. TokenData represents payload stored in JWT tokens
3. TokenVerify is used when services need to validate tokens
4. TokenVerifyResponse returns validation results

## Security
- Schemas enforce proper data types for token handling
- Structured separation between token and user data
- Support for account locking mechanism
- Role-based access control through role attribute

## Dependencies
- Pydantic: For data validation and settings management
- UserOut schema: For returning user information in login responses

## Usage
These schemas are used by:
- Authentication endpoints for login/token generation
- Middleware for token verification
- API endpoints requiring user authentication
- Services validating tokens from other services

## Endpoints
No endpoints defined here; these schemas support authentication endpoints elsewhere.
"""
from pydantic import BaseModel
from typing import Optional
from app.schemas.user import UserOut  # Required for the LoginResponse schema

# Basic token response structure for authentication endpoints
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

# Data structure for information extracted from/stored in JWT tokens
class TokenData(BaseModel):
    id: Optional[int] = None
    nickname: Optional[str] = None
    role: Optional[str] = None
    email: Optional[str] = None 
    secret: Optional[str] = None
    lock: Optional[bool] = None 
    customer_account: Optional[str] = None

# Schema for service-to-service token verification requests
class TokenVerify(BaseModel):
    service_token: str
    user_token: str

# Response schema for token verification results
class TokenVerifyResponse(BaseModel):
    id: int
    email: str
    nickname: str
    role: str
    valid: bool = True
    lock: bool = False 
    customer_account: str = "none"

# Enhanced login response combining token and user information
class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut
