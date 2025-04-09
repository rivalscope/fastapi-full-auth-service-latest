"""
Purpose:
This module defines the SQLAlchemy ORM model for managing user data in the login system.

Functionality:
- Maps the `users` table in the database to the `User` class.
- Stores user-related data such as personal information, authentication credentials, and security settings.
- Provides a foundation for user authentication, authorization, and session management.

Flow:
1. The `User` class inherits from SQLAlchemy's `Base` class.
2. Each attribute in the class corresponds to a column in the `users` table.
3. The database handles user data storage and retrieval through this model.

Security:
- Passwords are stored as hashed values (bcrypt or similar).
- Includes fields for session management (e.g., `iddle_time`) and account security (e.g., `lock`).
- Supports token-based authentication using the `token` field.

Dependencies:
- SQLAlchemy for ORM functionality.
- `app.users_database` for the `Base` class and database connection.

Usage:
- Import this module to interact with the `users` table in the database.
- Use this model for creating, reading, updating, and deleting user records.

Endpoints:
This module does not define any endpoints directly. It is used by other modules in the application to handle user-related database operations.
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime  # SQLAlchemy imports for defining model columns and data types
from sqlalchemy.sql import func  # SQL function import for default timestamp values
from app.utils.db import Base  # Import the Base class that connects the ORM model to the database

# Define the User model class that maps to the 'users' table in the database
class User(Base):
    __tablename__ = "users"  # Specify the database table name

    id = Column(Integer, primary_key=True, index=True)  # Primary key column for unique user identification
    nickname = Column(String, index=True)  # User's display name, indexed for faster queries
    email = Column(String, unique=True, index=True, nullable=False)  # User's email address, must be unique and not null
    password = Column(String, nullable=False)  # User's password stored as a hashed value, cannot be null
    role = Column(String, default="user")  # User's role for permission management, defaults to 'user'
    customer_account = Column(String, default="none")  # Links users to their subscription/payment info, defaults to 'none'
    passphrase = Column(String, default="none")  # Links users to their subscription/payment info, defaults to 'none'
    token = Column(String, nullable=True)  # JWT token for authentication, nullable when not logged in
    iddle_time = Column(DateTime, default=func.now())  # Timestamp of the user's last activity for session timeout
    secret = Column(String(24), nullable=True)  # Random 24-character string for token encryption
    lock = Column(Boolean, default=False)  # Account lock status, defaults to False (unlocked)

