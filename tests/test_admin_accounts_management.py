import pytest
import requests
import uuid

BASE_URL = "http://localhost:8000"

def create_admin_and_get_token():
    """Helper function to create an admin user and get auth token
    
    Note: This assumes the first registered user becomes an admin
    """
    # Register an admin user (first user in system is admin)
    unique_email = f"admin_{uuid.uuid4().hex[:8]}@example.com"
    unique_nickname = f"admin_{uuid.uuid4().hex[:8]}"
    password = "AdminSecure123!"
    
    register_response = requests.post(f"{BASE_URL}/register", json={
        "email": unique_email,
        "nickname": unique_nickname,
        "password": password,
        "customer_account": "none",
        "passphrase": "admin test passphrase"
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

def create_regular_user():
    """Helper function to create a regular user and return their ID"""
    unique_email = f"user_{uuid.uuid4().hex[:8]}@example.com"
    unique_nickname = f"user_{uuid.uuid4().hex[:8]}"
    
    response = requests.post(f"{BASE_URL}/register", json={
        "email": unique_email,
        "nickname": unique_nickname,
        "password": "RegularSecure123!",
        "customer_account": "none",
        "passphrase": "regular test passphrase"
    })
    
    if response.status_code not in (201, 200):
        return None
    
    return response.json()["id"]

def test_admin_access_without_token():
    """Test admin endpoints reject unauthenticated requests"""
    response = requests.get(f"{BASE_URL}/accounts_management/")
    assert response.status_code in (401, 403, 422)

def test_list_users():
    """Test admin can list all users"""
    admin_token = create_admin_and_get_token()
    if not admin_token:
        pytest.skip("Failed to create admin user")
    
    response = requests.get(
        f"{BASE_URL}/accounts_management/?token={admin_token}"
    )
    
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if len(data) > 0:
        assert "nickname" in data[0]
        assert "email" in data[0]
        assert "id" in data[0]

def test_get_user_by_id():
    """Test admin can get details for a specific user"""
    admin_token = create_admin_and_get_token()
    if not admin_token:
        pytest.skip("Failed to create admin user")
    
    # Create a user to fetch
    user_id = create_regular_user()
    if not user_id:
        pytest.skip("Failed to create regular user")
    
    response = requests.get(
        f"{BASE_URL}/accounts_management/{user_id}?token={admin_token}"
    )
    
    assert response.status_code == 200
    data = response.json()
    assert "id" in data and data["id"] == user_id
    assert "email" in data
    assert "nickname" in data

def test_update_user():
    """Test admin can update user information"""
    admin_token = create_admin_and_get_token()
    if not admin_token:
        pytest.skip("Failed to create admin user")
    
    # Create a user to update
    user_id = create_regular_user()
    if not user_id:
        pytest.skip("Failed to create regular user")
    
    # Update user data
    update_data = {
        "nickname": "Updated User Name",
        "lock": False
    }
    
    response = requests.put(
        f"{BASE_URL}/accounts_management/{user_id}?token={admin_token}",
        json=update_data
    )
    
    assert response.status_code == 200
    
    # Verify the update
    verify_response = requests.get(
        f"{BASE_URL}/accounts_management/{user_id}?token={admin_token}"
    )
    
    assert verify_response.status_code == 200
    updated_user = verify_response.json()
    assert updated_user["nickname"] == update_data["nickname"]
    assert updated_user["lock"] == update_data["lock"]

def test_delete_user():
    """Test admin can delete a user"""
    admin_token = create_admin_and_get_token()
    if not admin_token:
        pytest.skip("Failed to create admin user")
    
    # Create a user to delete
    user_id = create_regular_user()
    if not user_id:
        pytest.skip("Failed to create regular user")
    
    # Delete the user
    delete_response = requests.delete(
        f"{BASE_URL}/accounts_management/{user_id}?token={admin_token}"
    )
    
    assert delete_response.status_code == 200
    
    # Verify user no longer exists
    verify_response = requests.get(
        f"{BASE_URL}/accounts_management/{user_id}?token={admin_token}"
    )
    
    assert verify_response.status_code == 404
