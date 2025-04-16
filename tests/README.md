# FastAPI Auth Service Test Suite

This directory contains automated tests for the authentication service. These tests are designed to run against a live FastAPI instance (default: http://localhost:8000).

## Running All Tests

1. **Start your FastAPI app** :
   ```bash
   python3 main.py
   ```


2. **Run all tests:**
   ```bash
   ./run_tests.sh
   ```
   or
   ```bash
   pytest
   ```

## Running Individual Tests

Run a specific test file with:
```bash
pytest tests/test_users_auth.py
```

## Notes
- These tests use the `requests` library to make real HTTP calls to your running API.
- Make sure your API is running and accessible at the expected BASE_URL (default: http://localhost:8000).
- Some tests expect certain users or data to exist in the database, or may create new users.
- Requires `pytest` and `requests` (install with `pip install pytest requests`).
- If you get permission errors, make the script executable:
  ```bash
  chmod +x ./run_tests.sh
  ```
