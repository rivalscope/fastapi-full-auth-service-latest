"""
Integrated Test Suite for FastAPI Authentication Service
=======================================================

This file combines all test cases from the various test modules into a single
comprehensive test suite with proper setup and teardown procedures.

Key features:
- Centralizes all tests in a single file for easier maintenance
- Creates a single admin user as the first registered user
- Ensures proper cleanup by deleting the admin user at the end
- Maintains test isolation using fixtures
- Preserves all test functionality from the original test files

Organization:
- Setup and teardown fixtures at the module level
- Utility functions for user creation and authentication
- Tests grouped by functional area (registration, auth, recovery, etc.)

Note: This test suite requires the FastAPI auth service to be running
at the URL specified by BASE_URL.
"""

import pytest
import requests
import uuid
import os
import sys
import logging
from typing import Dict, Tuple, List, Any, Optional

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from sqlalchemy.orm import Session
from app.models.users_table import User
from app.utils.security import get_password_hash
from app.utils.db import get_db

# Terminal colors for test output
BOLD = "\033[1m"
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"

# Configuration
BASE_URL = "http://localhost:8000"
TEST_USERS = []  # Global list to track created users for cleanup
ADMIN_USER = {"id": None, "email": None, "password": None, "token": None}  # Single admin user

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --------------------------------
# Test Fixtures and Utilities
# --------------------------------
@pytest.fixture(scope="module", autouse=True)
def setup_and_cleanup():
    """Fixture to set up admin user and clean up after tests"""
    # Setup - runs before tests
    create_admin_user()
    
    yield
    
    # Teardown - runs after tests
    logger.info(f"Cleaning up {len(TEST_USERS)} test users")
    
    # Delete all test users using admin token
    if ADMIN_USER["token"]:
        for user_id in TEST_USERS:
            try:
                # Delete test user through admin API
                requests.delete(
                    f"{BASE_URL}/accounts_management/{user_id}",
                    headers={"Authorization": f"Bearer {ADMIN_USER['token']}"}
                )
                logger.info(f"Deleted test user with ID: {user_id}")
            except Exception as e:
                logger.error(f"Failed to delete user {user_id}: {e}")
    
    # Finally, delete the admin user using the user's self-delete endpoint
    if ADMIN_USER["token"]:
        try:
            delete_response = requests.delete(
                f"{BASE_URL}/my_account/delete",
                headers={"Authorization": f"Bearer {ADMIN_USER['token']}"}
            )
            if delete_response.status_code == 200:
                logger.info(f"Admin user {ADMIN_USER['id']} successfully deleted through self-delete endpoint")
            else:
                logger.error(f"Failed to delete admin user: {delete_response.status_code}")
        except Exception as e:
            logger.error(f"Error while deleting admin user: {e}")

def create_admin_user():
    """Create a single admin user for the test suite (first registered user is admin)"""
    # Generate unique credentials
    unique_email = f"admin_{uuid.uuid4().hex[:8]}@example.com"
    unique_nickname = f"admin_{uuid.uuid4().hex[:8]}"
    password = "AdminSecure123!"
    
    # Register the first user - it automatically becomes an admin
    response = requests.post(f"{BASE_URL}/register", json={
        "email": unique_email,
        "nickname": unique_nickname,
        "password": password,
        "customer_account": "none",
        "passphrase": "admin test passphrase"
    })
    
    if response.status_code in (201, 200):
        user_id = response.json()["id"]
        
        # Store the admin user details
        ADMIN_USER["id"] = user_id
        ADMIN_USER["email"] = unique_email
        ADMIN_USER["password"] = password
        
        # Log in to get the admin token
        login_response = requests.post(f"{BASE_URL}/login", json={
            "email": unique_email,
            "password": password
        })
        
        if login_response.status_code == 200:
            ADMIN_USER["token"] = login_response.json()["access_token"]
            logger.info(f"Admin user created with ID: {user_id}")
        else:
            logger.error(f"Failed to login as admin: {login_response.status_code}")
    else:
        logger.error(f"Failed to create admin user: {response.status_code}")

def get_admin_token() -> Optional[str]:
    """Get the admin token, refreshing if needed"""
    if not ADMIN_USER["token"]:
        # Try to log in again if token is missing
        if ADMIN_USER["email"] and ADMIN_USER["password"]:
            login_response = requests.post(f"{BASE_URL}/login", json={
                "email": ADMIN_USER["email"],
                "password": ADMIN_USER["password"]
            })
            
            if login_response.status_code == 200:
                ADMIN_USER["token"] = login_response.json()["access_token"]
    
    return ADMIN_USER["token"]

def create_regular_user() -> Optional[int]:
    """Create a regular user and return their ID"""
    unique_email = f"user_{uuid.uuid4().hex[:8]}@example.com"
    unique_nickname = f"user_{uuid.uuid4().hex[:8]}"
    password = "RegularSecure123!"
    
    response = requests.post(f"{BASE_URL}/register", json={
        "email": unique_email,
        "nickname": unique_nickname,
        "password": password,
        "customer_account": "none",
        "passphrase": "regular test passphrase"
    })
    
    if response.status_code not in (201, 200):
        logger.error(f"Failed to register regular user: {response.status_code}")
        return None
    
    user_id = response.json()["id"]
    TEST_USERS.append(user_id)  # Add to cleanup list
    return user_id

def create_user_with_details() -> Tuple[str, str, str, int]:
    """Create a user and return email, password, nickname, and ID"""
    unique_email = f"user_{uuid.uuid4().hex[:8]}@example.com"
    unique_nickname = f"user_{uuid.uuid4().hex[:8]}"
    password = "SecurePassword123!"
    
    response = requests.post(f"{BASE_URL}/register", json={
        "email": unique_email,
        "nickname": unique_nickname,
        "password": password,
        "customer_account": "none",
        "passphrase": "four words as passphrase"
    })
    
    if response.status_code not in (201, 200):
        return None, None, None, None
    
    user_id = response.json()["id"]
    TEST_USERS.append(user_id)  # Add to cleanup list
    return unique_email, password, unique_nickname, user_id

def create_user_for_recovery() -> Tuple[str, str, str]:
    """Create a user for testing recovery functionality"""
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
    
    user_id = response.json()["id"]
    TEST_USERS.append(user_id)  # Add to cleanup list
    return unique_email, password, recovery_passphrase

# --------------------------------
# User Registration Tests
# --------------------------------
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
        TEST_USERS.append(data["id"])  # Add to cleanup list
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
    
    # Track for cleanup
    TEST_USERS.append(response1.json()["id"])
    
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

# --------------------------------
# User Authentication Tests
# --------------------------------
def test_login_with_valid_credentials():
    """Test user can login with valid credentials"""
    # First create a new user
    email, password, _, user_id = create_user_with_details()
    if not email:
        pytest.skip("Failed to create test user")
    
    # Now try to login
    response = requests.post(f"{BASE_URL}/login", json={
        "email": email,
        "password": password
    })
    
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "token_type" in data and data["token_type"].lower() == "bearer"  # Case-insensitive check

def test_login_with_invalid_credentials():
    """Test login fails with invalid credentials"""
    # First create a new user
    email, password, _, _ = create_user_with_details()
    if not email:
        pytest.skip("Failed to create test user")
    
    # Try with wrong password
    response = requests.post(f"{BASE_URL}/login", json={
        "email": email,
        "password": "WrongPassword123!"
    })
    
    assert response.status_code == 401

def test_login_nonexistent_user():
    """Test login fails for non-existent user"""
    response = requests.post(f"{BASE_URL}/login", json={
        "email": f"nonexistent_{uuid.uuid4().hex[:8]}@example.com",
        "password": "SomePassword123!"
    })
    
    assert response.status_code == 401

def test_logout():
    """Test user logout functionality"""
    # First create and login a user
    email, password, _, _ = create_user_with_details()
    if not email:
        pytest.skip("Failed to create test user")
    
    login_response = requests.post(f"{BASE_URL}/login", json={
        "email": email,
        "password": password
    })
    
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    
    # Now logout using Bearer authentication
    logout_response = requests.post(
        f"{BASE_URL}/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert logout_response.status_code == 200
    
    # Verify token is invalidated by trying to access a protected route
    verify_response = requests.get(
        f"{BASE_URL}/my_account/", 
        headers={"Authorization": f"Bearer {token}"}
    )
    assert verify_response.status_code == 401

# --------------------------------
# Account Recovery Tests
# --------------------------------
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

# --------------------------------
# User Account Management Tests
# --------------------------------
def test_get_account_info():
    """Test retrieving the user's account information"""
    # Create a test user and get token
    email, password, nickname, _ = create_user_with_details()
    if not email:
        pytest.skip("Failed to create test user")
    
    login_response = requests.post(f"{BASE_URL}/login", json={
        "email": email,
        "password": password
    })
    
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    
    # Get account info using Bearer authentication
    response = requests.get(
        f"{BASE_URL}/my_account/",
        headers={"Authorization": f"Bearer {token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "email" in data and data["email"] == email
    assert "nickname" in data and data["nickname"] == nickname

def test_update_account_info():
    """Test updating the user's account information"""
    # Create a test user and get token
    email, password, _, _ = create_user_with_details()
    if not email:
        pytest.skip("Failed to create test user")
    
    login_response = requests.post(f"{BASE_URL}/login", json={
        "email": email,
        "password": password
    })
    
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    
    # Update account info using Bearer authentication
    new_nickname = f"updated_{uuid.uuid4().hex[:8]}"
    update_data = {"nickname": new_nickname}
    
    response = requests.put(
        f"{BASE_URL}/my_account/",
        headers={"Authorization": f"Bearer {token}"},
        json=update_data
    )
    
    assert response.status_code == 200
    
    # Verify the update using Bearer authentication
    verify_response = requests.get(
        f"{BASE_URL}/my_account/",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert verify_response.status_code == 200
    updated_data = verify_response.json()
    assert updated_data["nickname"] == new_nickname

def test_delete_account():
    """Test the user can delete their own account"""
    # Create a test user and get token
    email, password, _, _ = create_user_with_details()
    if not email:
        pytest.skip("Failed to create test user")
    
    login_response = requests.post(f"{BASE_URL}/login", json={
        "email": email,
        "password": password
    })
    
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    
    # Delete account using Bearer authentication
    response = requests.delete(
        f"{BASE_URL}/my_account/delete",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    
    # Try to access account after deletion (should fail)
    verify_response = requests.get(
        f"{BASE_URL}/my_account/",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert verify_response.status_code == 401

# --------------------------------
# Admin Account Management Tests
# --------------------------------
def test_admin_access_without_token():
    """Test admin endpoints reject unauthenticated requests"""
    response = requests.get(f"{BASE_URL}/accounts_management/")
    assert response.status_code in (401, 403, 422)

def test_admin_list_users():
    """Test admin can list all users"""
    admin_token = get_admin_token()
    if not admin_token:
        pytest.skip("Failed to get admin token")
    
    response = requests.get(
        f"{BASE_URL}/accounts_management/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if len(data) > 0:
        assert "nickname" in data[0]
        assert "email" in data[0]
        assert "id" in data[0]

def test_admin_get_user_by_id():
    """Test admin can get details for a specific user"""
    admin_token = get_admin_token()
    if not admin_token:
        pytest.skip("Failed to get admin token")
    
    # Create a user to fetch
    user_id = create_regular_user()
    if not user_id:
        pytest.skip("Failed to create regular user")
    
    response = requests.get(
        f"{BASE_URL}/accounts_management/{user_id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "id" in data and data["id"] == user_id
    assert "email" in data
    assert "nickname" in data

def test_admin_update_user():
    """Test admin can update user information"""
    admin_token = get_admin_token()
    if not admin_token:
        pytest.skip("Failed to get admin token")
    
    # Create a user to update
    user_id = create_regular_user()
    if not user_id:
        pytest.skip("Failed to create regular user")
    
    # Update user data
    update_data = {
        "nickname": f"admin_updated_{uuid.uuid4().hex[:8]}",
        "lock": False
    }
    
    response = requests.put(
        f"{BASE_URL}/accounts_management/{user_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
        json=update_data
    )
    
    assert response.status_code == 200
    
    # Verify the update
    verify_response = requests.get(
        f"{BASE_URL}/accounts_management/{user_id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert verify_response.status_code == 200
    updated_user = verify_response.json()
    assert updated_user["nickname"] == update_data["nickname"]
    assert updated_user["lock"] == update_data["lock"]

def test_admin_delete_user():
    """Test admin can delete a user"""
    admin_token = get_admin_token()
    if not admin_token:
        pytest.skip("Failed to get admin token")
    
    # Create a user to delete
    user_id = create_regular_user()
    if not user_id:
        pytest.skip("Failed to create regular user")
    
    # Delete the user
    delete_response = requests.delete(
        f"{BASE_URL}/accounts_management/{user_id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert delete_response.status_code == 200
    
    # Verify user no longer exists
    verify_response = requests.get(
        f"{BASE_URL}/accounts_management/{user_id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert verify_response.status_code == 404
    
    # Remove from cleanup list as it's already deleted
    if user_id in TEST_USERS:
        TEST_USERS.remove(user_id)

# --------------------------------
# Inter-service Token Validation Tests
# --------------------------------
def test_token_validation():
    """Test the inter-service token validation endpoint"""
    # Create a user and get token
    email, password, _, _ = create_user_with_details()
    if not email:
        pytest.skip("Failed to create test user")
    
    login_response = requests.post(f"{BASE_URL}/login", json={
        "email": email,
        "password": password
    })
    
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    
    # Get the service token from settings
    from app.utils.config import settings
    service_token = settings.SERVICE_TOKEN
    
    # Verify token with the inter-service endpoint using both authentication headers
    verify_response = requests.post(
        f"{BASE_URL}/verify",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Service-Token": service_token
        }
    )
    
    assert verify_response.status_code == 200
    data = verify_response.json()
    assert "id" in data
    assert "email" in data
    assert "nickname" in data
    assert "role" in data
    assert "customer_account" in data

# --------------------------------
# Login Status Tests
# --------------------------------
def test_login_sets_logged_in_flag():
    """Test that logging in sets the is_logged_in flag to True"""
    # First create a new user
    email, password, _, user_id = create_user_with_details()
    if not email:
        pytest.skip("Failed to create test user")
    
    # Login with the user
    login_response = requests.post(f"{BASE_URL}/login", json={
        "email": email,
        "password": password
    })
    
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    
    # Get admin token to check user details
    admin_token = get_admin_token()
    if not admin_token:
        pytest.skip("Failed to get admin token")
    
    # Check that is_logged_in is True through the admin API
    user_response = requests.get(
        f"{BASE_URL}/accounts_management/{user_id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert user_response.status_code == 200
    user_data = user_response.json()
    assert "is_logged_in" in user_data
    assert user_data["is_logged_in"] is True

def test_logout_unsets_logged_in_flag():
    """Test that logging out sets the is_logged_in flag to False"""
    # First create a new user
    email, password, _, user_id = create_user_with_details()
    if not email:
        pytest.skip("Failed to create test user")
    
    # Login with the user
    login_response = requests.post(f"{BASE_URL}/login", json={
        "email": email,
        "password": password
    })
    
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    
    # Log the user out
    logout_response = requests.post(
        f"{BASE_URL}/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert logout_response.status_code == 200
    
    # Get admin token to check user details
    admin_token = get_admin_token()
    if not admin_token:
        pytest.skip("Failed to get admin token")
    
    # Check that is_logged_in is False through the admin API
    user_response = requests.get(
        f"{BASE_URL}/accounts_management/{user_id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert user_response.status_code == 200
    user_data = user_response.json()
    assert "is_logged_in" in user_data
    assert user_data["is_logged_in"] is False

def test_admin_can_see_login_status_in_list():
    """Test that admin can see login status when listing users"""
    # Create and log in a user
    email, password, _, user_id = create_user_with_details()
    if not email:
        pytest.skip("Failed to create test user")
    
    login_response = requests.post(f"{BASE_URL}/login", json={
        "email": email,
        "password": password
    })
    
    assert login_response.status_code == 200
    
    # Get admin token
    admin_token = get_admin_token()
    if not admin_token:
        pytest.skip("Failed to get admin token")
    
    # Get the list of users through admin API
    list_response = requests.get(
        f"{BASE_URL}/accounts_management/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert list_response.status_code == 200
    users = list_response.json()
    
    # Find our test user in the list
    test_user = next((user for user in users if user["id"] == user_id), None)
    assert test_user is not None
    assert "is_logged_in" in test_user
    assert test_user["is_logged_in"] is True

def test_idle_duration_format():
    """Test that the idle_duration field is properly formatted"""
    # Create and log in a user
    email, password, _, user_id = create_user_with_details()
    if not email:
        pytest.skip("Failed to create test user")
    
    login_response = requests.post(f"{BASE_URL}/login", json={
        "email": email,
        "password": password
    })
    
    assert login_response.status_code == 200
    
    # Get admin token to check user details
    admin_token = get_admin_token()
    if not admin_token:
        pytest.skip("Failed to get admin token")
    
    # Check that idle_duration is formatted correctly
    user_response = requests.get(
        f"{BASE_URL}/accounts_management/{user_id}",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    assert user_response.status_code == 200
    user_data = user_response.json()
    
    # Verify the idle_duration field exists and has the proper format
    assert "idle_duration" in user_data
    
    # The format should be either "X sec" or "X min Y sec"
    duration = user_data["idle_duration"]
    assert duration is not None
    
    # Simple format check - should contain "sec"
    assert "sec" in duration

# Run tests with colored output when run directly
if __name__ == "__main__":
    print(f"{BOLD}Running FastAPI Auth Service Test Suite{RESET}")
    pytest.main(["-v", __file__])