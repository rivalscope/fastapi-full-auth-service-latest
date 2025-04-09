"""
Password Utility Module
=======================

Purpose:
--------
This module provides secure password handling functionality for authentication processes in the login system,
allowing for safe password storage and verification.

Functionality:
-------------
- Password hashing using bcrypt algorithm
- Password verification against stored hashes
- Configurable security parameters through CryptContext

Flow:
-----
1. When users register or change passwords, plain text passwords are hashed via get_password_hash()
2. During login, verify_password() compares submitted passwords against stored hashes

Security:
--------
- Uses bcrypt with 12 rounds (2^12 iterations) to resist brute-force attacks
- Automatically generates and stores unique salts within each hash
- Never stores plain text passwords
- BCrypt is deliberately slow to increase security against attacks

Dependencies:
------------
- passlib.context: Provides CryptContext for handling password hashing operations

Usage:
------
To hash a password:
    hashed_password = get_password_hash("my_secure_password")

To verify a password:
    is_correct = verify_password("submitted_password", stored_hash)
"""

from passlib.context import CryptContext

# Configure password hashing with bcrypt using recommended security settings
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__ident="2b",
    bcrypt__min_rounds=12
)

def verify_password(plain_password, hashed_password):
    """Compare a plain text password against its hashed version to verify user credentials"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Generate a secure hash from a plain text password for storage in database"""
    return pwd_context.hash(password)
