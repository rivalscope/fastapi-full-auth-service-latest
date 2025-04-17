# FastAPI Auth Service Test Suite

This directory contains an integrated automated test suite for the authentication service. All tests have been consolidated into a single comprehensive file (`test_integrated.py`) for easier maintenance and execution. The tests are designed to run against a live FastAPI instance (default: http://localhost:8000).

## Running Tests

1. **Start your FastAPI app** :
   ```bash
   python3 main.py
   ```

2. **Run the integrated test suite:**
   ```bash
   pytest 
   ```

## Test Organization

The integrated test file includes tests for:
- User registration
- User authentication and login/logout
- Password recovery
- User account management
- Admin account management
- Inter-service token validation

## Test Approach

The test suite follows a clean and efficient testing approach:

1. A single admin user is created at the beginning of testing (first registered user becomes admin)
2. Regular test users are created as needed and tracked for cleanup
3. All tests execute against the live API endpoints
4. At test completion, the admin user:
   - Deletes all regular test users via admin API
   - Deletes itself using the self-delete endpoint

This approach ensures the database remains clean after testing, with no leftover test accounts.

## Notes
- These tests use the `requests` library to make real HTTP calls to your running API.
- Make sure your API is running and accessible at the expected BASE_URL (default: http://localhost:8000).
- The test suite automatically cleans up all created users, including the admin.
- Requires `pytest` library to run tests.
