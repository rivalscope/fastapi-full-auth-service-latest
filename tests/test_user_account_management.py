import pytest
import requests
import uuid

BASE_URL = "http://localhost:8000"

def get_auth_token():
    """Helper function to get a valid authentication token"""
    # Register a new user
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
    
    # Login to get token
    login_response = requests.post(f"{BASE_URL}/login", json={
        "email": unique_email,
        "password": password
    })
    
    if login_response.status_code != 200:
        return None
    
    return login_response.json()["access_token"]

def test_get_profile_authenticated():
    """Test getting user profile with valid authentication"""
    token = get_auth_token()
    if not token:
        pytest.skip("Failed to get authentication token")
    
    response = requests.get(
        f"{BASE_URL}/my_account/?token={token}"
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "nickname" in data
    assert "email" in data

def test_get_profile_unauthenticated():
    """Test getting user profile without authentication"""
    response = requests.get(f"{BASE_URL}/my_account/")
    assert response.status_code == 401 or response.status_code == 422

def test_update_profile():
    """Test updating user profile"""
    token = get_auth_token()
    if not token:
        pytest.skip("Failed to get authentication token")
    
    # Get current profile
    get_response = requests.get(
        f"{BASE_URL}/my_account/?token={token}"
    )
    
    if get_response.status_code != 200:
        pytest.skip("Failed to get current profile")
    
    current_profile = get_response.json()
    new_nickname = f"Updated_{uuid.uuid4().hex[:5]}"
    
    # Update profile
    update_response = requests.put(
        f"{BASE_URL}/my_account/?token={token}",
        json={
            "nickname": new_nickname
        }
    )
    
    assert update_response.status_code == 200
    
    # Verify changes
    verify_response = requests.get(
        f"{BASE_URL}/my_account/?token={token}"
    )
    
    assert verify_response.status_code == 200
    updated_profile = verify_response.json()
    assert updated_profile["nickname"] == new_nickname

def test_delete_account():
    """Test deleting user account"""
    token = get_auth_token()
    if not token:
        pytest.skip("Failed to get authentication token")
    
    # Delete the account
    delete_response = requests.delete(
        f"{BASE_URL}/my_account/delete?token={token}"
    )
    
    assert delete_response.status_code == 200
    
    # Verify account no longer works
    verify_response = requests.get(
        f"{BASE_URL}/my_account/?token={token}"
    )
    
    assert verify_response.status_code == 401 or verify_response.status_code == 403
