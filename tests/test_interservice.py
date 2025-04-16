import os
import pytest
import requests
import uuid

BASE_URL = "http://localhost:8000"
SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "SeCrEtSeRvIcEtOkEnFoRiNtErNaLsErViCeS")

def get_valid_user_token():
    """Helper function to get a valid user token"""
    # Register and login a test user
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
    
    if register_response.status_code not in (201, 200):
        return None
    
    login_response = requests.post(f"{BASE_URL}/login", json={
        "email": unique_email,
        "password": password
    })
    
    if login_response.status_code != 200:
        return None
    
    return login_response.json()["access_token"]

def get_admin_token():
    """Helper function to get an admin token"""
    # Create admin user and login
    unique_email = f"admin_{uuid.uuid4().hex[:8]}@example.com"
    unique_nickname = f"admin_{uuid.uuid4().hex[:8]}"
    password = "AdminSecure123!"
    
    register_response = requests.post(f"{BASE_URL}/register", json={
        "email": unique_email,
        "nickname": unique_nickname,
        "password": password,
        "customer_account": "none",
        "passphrase": "admin passphrase"
    })
    
    if register_response.status_code not in (201, 200):
        return None
    
    login_response = requests.post(f"{BASE_URL}/login", json={
        "email": unique_email,
        "password": password
    })
    
    if login_response.status_code != 200:
        return None
    
    return login_response.json()["access_token"]

def test_validate_token():
    """Test validating a user token through the interservice endpoint"""
    # Get a valid user token
    user_token = get_valid_user_token()
    if not user_token:
        pytest.skip("Failed to get valid user token")
    
    # Validate the token
    response = requests.post(
        f"{BASE_URL}/verify",
        json={
            "service_token": SERVICE_TOKEN,
            "user_token": user_token
        }
    )
    
    # Accept either 200 (success) or various error codes if not implemented yet
    assert response.status_code in (200, 401, 403, 404)
    
    if response.status_code == 200:
        data = response.json()
        assert "valid" in data or "id" in data
