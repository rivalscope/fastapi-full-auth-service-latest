# FastAPI Authentication Service

A robust, secure authentication and user management service built with FastAPI.

## Features

- **User Authentication**: Secure login/logout with JWT token management
- **User Registration**: New user account creation with validation
- **Password Recovery**: Self-service account recovery via passphrase
- **Account Management**: User account self-management capabilities
- **Admin Controls**: Admin panel for user account administration
- **Inter-service Validation**: Token validation for microservice architecture
- **Security Best Practices**: Password hashing, validation, and token security
- **Complete Test Suite**: Comprehensive API testing

## Getting Started

### Prerequisites

- Python 3.8+
- pip package manager

### Installation

1. Clone the repository
```bash
git clone https://your-repository-url/fastapi_auth_service.git
cd fastapi_auth_service
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

3. Configure environment (rename .env.example to .env if available)

4. Start the service
```bash
python main.py
```

The API will be available at http://localhost:8000 with interactive documentation at http://localhost:8000/docs

## Testing

The service includes a comprehensive test suite that verifies all API endpoints and functionality.

### Running Tests

1. Start the service on the default port
```bash
python main.py
```

2. In a separate terminal, run the tests
```bash
cd tests
pytest
```

### Test Design

- Tests are consolidated in a single file (`tests/test_integrated.py`) for easier maintenance
- The first user registered becomes an admin automatically
- Tests cover all major API functions including registration, authentication, account management, and admin operations
- The test suite handles its own cleanup, leaving no test data in the system

### Cleanup Process

The testing framework implements an intelligent cleanup strategy:
1. A single admin user is created at the beginning of test execution
2. Regular test users are tracked during test execution
3. At the end of testing:
   - All test users are removed using admin API endpoints
   - The admin user removes itself using the self-delete endpoint
   - The database is left in a clean state with no test users

## Project Structure

```
fastapi_auth_service/
├── app/                    # Core application code
│   ├── models/             # Database models
│   ├── routers/            # API endpoint routers
│   ├── schemas/            # Pydantic schemas
│   └── utils/              # Utility functions and helpers
├── docs/                   # Documentation
├── logs/                   # Log files
├── tests/                  # Test suite
├── main.py                 # Application entry point
└── requirements.txt        # Dependencies
```

## Documentation

For more detailed documentation, see the [docs](./docs) directory:
- [API Reference](./docs/api_reference.md)
- [How It Works](./docs/how_it_works.md)

## License

[Your license information]