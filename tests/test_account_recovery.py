import pytest
import requests
import uuid

BASE_URL = "http://localhost:8000"

def create_user_for_recovery():
    """Helper function to create a user for testing recovery functionality"""
    unique_email = f"user_{uuid.uuid4().hex[:8]}@example.com"
    unique_nickname = f"user_{uuid.uuid4().hex[:8]}"
    password = "SecurePassword123!"
    recovery_passphrase = "four words as passphrase"
    
    response = requests.post(f"{BASE_URL}/register", json={
        "email": unique_email,
        "nickname": unique_nickname,
        "password": password,
        "customer_account": "none",
        "passphrase": recovery_passphrase
    })
    
    if response.status_code not in (201, 200):
        return None, None, None
    
    return unique_email, password, recovery_passphrase

def test_recover_password():
    """Test password recovery with valid passphrase"""
    # Create a test user
    email, old_password, passphrase = create_user_for_recovery()
    if not email:
        pytest.skip("Failed to create test user")
    
    # Test password recovery
    new_password = f"NewSecure{uuid.uuid4().hex[:8]}!"
    
    response = requests.post(f"{BASE_URL}/recovery", json={
        "email": email,
        "passphrase": passphrase,
        "new_password": new_password
    })
    
    assert response.status_code == 200
    
    # Try logging in with the new password
    login_response = requests.post(f"{BASE_URL}/login", json={
        "email": email,
        "password": new_password
    })
    
    # Should be able to log in with new password
    assert login_response.status_code == 200
    assert "access_token" in login_response.json()

def test_recover_with_invalid_passphrase():
    """Test that recovery fails with invalid passphrase"""
    # Create a test user
    email, old_password, passphrase = create_user_for_recovery()
    if not email:
        pytest.skip("Failed to create test user")
    
    # Try with invalid passphrase
    new_password = f"NewSecure{uuid.uuid4().hex[:8]}!"
    
    response = requests.post(f"{BASE_URL}/recovery", json={
        "email": email,
        "passphrase": "wrong passphrase",
        "new_password": new_password
    })
    
    # Should be unauthorized or bad request
    assert response.status_code in (400, 401, 403)
    
    # Original password should still work
    login_response = requests.post(f"{BASE_URL}/login", json={
        "email": email,
        "password": old_password
    })
    
    assert login_response.status_code == 200