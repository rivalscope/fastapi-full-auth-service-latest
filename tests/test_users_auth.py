import pytest
import requests
import uuid

BASE_URL = "http://localhost:8000"

def test_login_with_valid_credentials():
    """Test login with valid credentials"""
    # First register a user for testing
    unique_email = f"user_{uuid.uuid4().hex[:8]}@example.com"
    unique_nickname = f"user_{uuid.uuid4().hex[:8]}"
    password = "SecurePassword123!"
    
    register_response = requests.post(f"{BASE_URL}/register", json={
        "email": unique_email,
        "nickname": unique_nickname,
        "password": password,
        "customer_account": "none",
        "passphrase": "four words as passphrase"
    })
    
    # Skip if registration failed
    if register_response.status_code not in (201, 200):
        pytest.skip("User registration failed, skipping login test")
    
    # Now try to login with the new user
    login_response = requests.post(f"{BASE_URL}/login", json={
        "email": unique_email,
        "password": password
    })
    
    assert login_response.status_code == 200
    data = login_response.json()
    assert "access_token" in data
    assert "token_type" in data
    assert data["token_type"] == "bearer"
    
    # Return token for other tests to use
    return data["access_token"]

def test_login_with_invalid_credentials():
    """Test login with invalid credentials"""
    response = requests.post(f"{BASE_URL}/login", json={
        "email": "nonexistent@example.com",
        "password": "wrongpassword123"
    })
    
    assert response.status_code == 401 or response.status_code == 403 or response.status_code == 422

def test_logout():
    """Test logout functionality"""
    # Get a valid token first
    token = test_login_with_valid_credentials()
    if token is None:
        pytest.skip("Login failed, skipping logout test")
    
    # Test logout
    response = requests.post(
        f"{BASE_URL}/logout?token={token}"
    )
    
    assert response.status_code == 200
    
    # Verify token is no longer valid by trying to use it
    verify_response = requests.get(
        f"{BASE_URL}/my_account/?token={token}"
    )
    
    assert verify_response.status_code == 401 or verify_response.status_code == 403
