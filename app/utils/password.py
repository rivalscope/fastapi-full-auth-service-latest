"""
Password Utility Module
=======================

Purpose:
--------
This module provides secure password handling functionality for authentication processes in the login system,
allowing for safe password storage and verification.

Functionality:
-------------
- Password hashing using modern cryptography library
- Password verification against stored hashes
- Secure key derivation functions (PBKDF2-HMAC-SHA256)

Flow:
-----
1. When users register or change passwords, plain text passwords are hashed via get_password_hash()
2. During login, verify_password() compares submitted passwords against stored hashes

Security:
--------
- Uses PBKDF2-HMAC-SHA256 with 600,000 iterations to resist brute-force attacks
- Automatically generates and stores unique salts within each hash
- Never stores plain text passwords
- Uses modern cryptography library instead of deprecated crypt module
- Format: algorithm$iterations$salt$hash
"""

import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend

# Security settings
SALT_SIZE = 16  # 128 bits, recommended size for salt
KEY_LENGTH = 32  # 256 bits
ITERATIONS = 600000  # Recommended minimum by OWASP for PBKDF2 as of 2023
ALGORITHM = "pbkdf2-sha256"  # Algorithm identifier for our hash format
ENCODING = "utf-8"  # Character encoding for strings

def get_password_hash(password: str) -> str:
    """
    Generate a secure hash from a plain text password for storage in database
    
    Args:
        password: Plain text password to hash
        
    Returns:
        String in format: algorithm$iterations$salt$hash
    """
    # Generate a random salt
    salt = os.urandom(SALT_SIZE)
    
    # Create the hash using PBKDF2-HMAC-SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    
    # Derive the key (password hash)
    key = kdf.derive(password.encode(ENCODING))
    
    # Encode salt and key as base64 for storage
    salt_b64 = base64.b64encode(salt).decode(ENCODING)
    key_b64 = base64.b64encode(key).decode(ENCODING)
    
    # Return a formatted hash string: algorithm$iterations$salt$hash
    return f"{ALGORITHM}${ITERATIONS}${salt_b64}${key_b64}"

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Compare a plain text password against its hashed version to verify user credentials
    
    Args:
        plain_password: Plain text password to verify
        hashed_password: Stored password hash to compare against
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        # Parse the hash string
        algorithm, iterations, salt_b64, key_b64 = hashed_password.split('$')
        
        # Ensure we're using the right algorithm
        if algorithm != ALGORITHM:
            return False
        
        # Decode the salt and iterations
        salt = base64.b64decode(salt_b64)
        iterations = int(iterations)
        
        # Create the PBKDF2 instance with the same parameters
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        
        # Decode the stored hash
        stored_key = base64.b64decode(key_b64)
        
        # Verify the password by comparing the derived key with the stored key
        try:
            kdf.verify(plain_password.encode(ENCODING), stored_key)
            return True
        except Exception:
            return False
    except Exception:
        # Any parsing or verification error means the password is invalid
        return False
