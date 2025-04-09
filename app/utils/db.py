"""
Database Configuration and Connection Management
================================================

Purpose:
    This module establishes and manages database connectivity for the application,
    providing the SQLAlchemy ORM infrastructure for data persistence.

Functionality:
    - Creates SQLAlchemy engine with appropriate connection settings
    - Initializes session factory for database interactions
    - Provides base class for declarative model definitions
    - Offers utility functions for database session management
    - Handles database and table initialization on application startup

Flow:
    1. Import required dependencies and configure logger
    2. Set up database connection URL from application settings
    3. Create SQLAlchemy engine with SQLite-specific connection arguments
    4. Initialize session factory for creating database sessions
    5. Define base class for ORM models
    6. Provide get_db function as a dependency for FastAPI routes
    7. Implement database initialization function for application startup

Security:
    - Uses settings from configuration module rather than hardcoded values
    - Implements proper session handling with automatic closure
    - Includes SQLite-specific connection arguments for thread safety
    - Ensures database sessions are properly closed through context management

Dependencies:
    - SQLAlchemy: ORM framework for database operations
    - os: For filesystem operations when checking database existence
    - app.config: Application configuration containing database connection settings
    - app.utils.logging: Custom logging utility for operational monitoring
    - app.models.user: User model imported during database initialization

Usage:
    - Import get_db() as a FastAPI dependency to get a database session
    - Call create_db_and_tables() during application startup
    - Use Base class for creating SQLAlchemy models

Endpoints:
    N/A - This is a utility module, not an endpoint handler
"""

import os
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker, declarative_base
from app.utils.config import settings
from app.utils.logging import get_logger

# Initialize logger for database operations
logger = get_logger(__name__)

# Configure database connection URL from application settings
SQLALCHEMY_DATABASE_URL = settings.DATABASE_URL
logger.info(f"Connecting to database at {SQLALCHEMY_DATABASE_URL}")

# Create SQLAlchemy engine with SQLite-specific thread safety settings
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})

# Create session factory for database interactions
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for declarative ORM models
Base = declarative_base()

def get_db():
    # Create new database session
    db = SessionLocal()
    logger.debug("Database session created")
    try:
        # Provide session to the caller
        yield db
    finally:
        # Ensure session is properly closed
        db.close()
        logger.debug("Database session closed")

def create_db_and_tables():
    # Extract file path from SQLite connection URL
    db_file = SQLALCHEMY_DATABASE_URL.replace("sqlite:///", "")
    
    # Check if database file already exists on disk
    if os.path.exists(db_file):
        logger.info(f"Database file {db_file} already exists")
        
        # Check if required tables already exist in database
        inspector = inspect(engine)
        if "users" in inspector.get_table_names():
            logger.info("Tables already exist, using existing database")
            return
    
    # Create database tables if they don't exist
    logger.info("Creating database tables")
    from app.models.users_table import User  # Import here to avoid circular imports
    
    # Create all tables defined in ORM models
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully")
