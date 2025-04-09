"""
Configuration Module for Login Service
======================================

Purpose:
    This module centralizes all configuration settings for the login service application.
    It provides a validated, type-checked settings object for application-wide use.

Functionality:
    - Loads environment variables from .env file
    - Validates environment variable types and values using Pydantic
    - Provides a centralized access point for all application settings
    - Ensures type safety for configuration values

Flow:
    1. Environment variables are loaded from .env file
    2. Settings class defines expected configuration values with types
    3. Pydantic validates all settings against their expected types
    4. A single settings instance is created for import by other modules

Security:
    - Securely handles sensitive configuration like database credentials and secret keys
    - Centralizes security parameters like token expiration and encryption algorithms
    - Controls rate limiting settings to prevent abuse of the service

Dependencies:
    - pydantic_settings: For settings validation and management
    - dotenv: For loading environment variables from .env file

Usage:
    from app.config import settings

    # Access settings as needed
    db_url = settings.DATABASE_URL
    token_expire = settings.ACCESS_TOKEN_EXPIRE_MINUTES
"""
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings(BaseSettings):
    # Database connection settings
    DATABASE_URL: str
    
    # Security and authentication settings
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int
    IDDLE_MINUTES: int
    SERVICE_TOKEN: str
    
    # Rate limiting configuration to prevent abuse
    RATE_LIMITS_PUBLIC_ROUTES: int
    RATE_LIMITS_PRIVATE_ROUTES: int
    RATE_LIMITS_PUBLIC_TIME_UNIT: str
    RATE_LIMITS_PRIVATE_TIME_UNIT: str
    
    # Application logging configuration
    LOG_LEVEL: str
    
    # Pydantic configuration for environment variable loading
    model_config = {
        "env_file": ".env",
        "case_sensitive": True
    }

# Create a singleton settings instance for import by other modules
settings = Settings()
