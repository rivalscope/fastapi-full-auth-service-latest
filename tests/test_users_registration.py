import pytest
import requests
import uuid

BASE_URL = "http://localhost:8000"

def test_register_new_user():
    """Test registering a new user with valid data"""
    unique_email = f"user_{uuid.uuid4().hex[:8]}@example.com"
    unique_nickname = f"user_{uuid.uuid4().hex[:8]}"
    
    response = requests.post(f"{BASE_URL}/register", json={
        "email": unique_email,
        "nickname": unique_nickname,
        "password": "SecurePassword123!",
        "customer_account": "none",
        "passphrase": "four words as passphrase"
    })
    
    assert response.status_code in (201, 200)
    if response.status_code in (201, 200):
        data = response.json()
        assert "id" in data
        assert "email" in data and data["email"] == unique_email
        assert "nickname" in data and data["nickname"] == unique_nickname

def test_register_with_weak_password():
    """Test registration fails with a weak password"""
    unique_email = f"user_{uuid.uuid4().hex[:8]}@example.com"
    unique_nickname = f"user_{uuid.uuid4().hex[:8]}"
    
    response = requests.post(f"{BASE_URL}/register", json={
        "email": unique_email,
        "nickname": unique_nickname,
        "password": "weak",  # Too weak
        "customer_account": "none",
        "passphrase": "four words as passphrase"
    })
    
    assert response.status_code == 400 or response.status_code == 422
    # Response should contain information about password requirements

def test_register_with_existing_nickname():
    """Test registration fails when nickname already exists"""
    # First, create a user
    email1 = f"user_{uuid.uuid4().hex[:8]}@example.com"
    nickname = f"user_{uuid.uuid4().hex[:8]}"
    
    response1 = requests.post(f"{BASE_URL}/register", json={
        "email": email1,
        "nickname": nickname,
        "password": "SecurePassword123!",
        "customer_account": "none",
        "passphrase": "four words as passphrase"
    })
    
    # Skip this test if the first registration failed
    if response1.status_code not in (201, 200):
        pytest.skip("First user registration failed, skipping duplicate test")
    
    # Try to register with the same nickname but different email
    email2 = f"user_{uuid.uuid4().hex[:8]}@example.com"
    response2 = requests.post(f"{BASE_URL}/register", json={
        "email": email2,
        "nickname": nickname,  # Same nickname
        "password": "SecurePassword123!",
        "customer_account": "none",
        "passphrase": "four words as passphrase"
    })
    
    assert response2.status_code == 400

def test_register_missing_fields():
    """Test registration fails when required fields are missing"""
    response = requests.post(f"{BASE_URL}/register", json={
        "email": "incomplete@example.com",
        # Missing nickname, password, etc.
    })
    
    assert response.status_code == 422  # FastAPI validation error code
