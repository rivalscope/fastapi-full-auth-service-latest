---
title: Authentication Service
date: April 17, 2025
author: Vasile Alecu AILaboratories.net
version: 1.0
status: Production Ready
---

# FastAPI Authentication Service

A robust, secure authentication and user management service built with FastAPI.

## Overview

The Auth Service is a comprehensive authentication and user management service built with FastAPI. It provides secure authentication, user registration, account management, logging, and inter-service token validation capabilities.

## Features

- **User Registration**: New user account creation with email verification
- **User Authentication**: Secure login/logout with JWT token management
- **Password Recovery**: Self-service account recovery via passphrase
- **Account Management**: User account self-management capabilities
- **Admin Controls**: Admin panel for user account administration
- **Inter-service Validation**: Token validation for microservice architecture
- **Security Best Practices**: Password hashing, validation, and token security
- **Comprehensive Logging**: Detailed logging and security features
- **Complete Test Suite**: Comprehensive API testing

## Documentation

For more detailed documentation, see the [docs](./docs) directory:

- [API Reference](./docs/api_reference.md) - Detailed API endpoint documentation
- [Project Structure](./docs/app_overview.md) - Overview of project organization
- [Docker Setup](./docs/docker.md) - Detailed Docker configuration documentation

## Getting Started

### Prerequisites

- Python 3.8+
- pip package manager

### Standard Setup

1. Clone the repository
```bash
git clone https://your-repository-url/fastapi_auth_service.git
cd fastapi_auth_service
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

3. Configure environment
Rename .env.example to .env and adjust values if needed

4. Start the FastAPI server
```bash
# From Windows
python main.py
# From Linux/Mac
python3 main.py
```

The API will be available at http://localhost:8000 with interactive documentation at http://localhost:8000/docs

### Docker Setup

To run the application using Docker, follow these steps:

1. **Build the Docker image**
```bash
docker compose build
```

2. **Start the containerized application**
```bash
docker compose up -d
```
The application will be available at http://localhost:8400/docs.

3. **View application logs**
```bash
docker compose logs -f auth_service
```

4. **Stop the containerized application**
```bash
docker compose down
```

#### Customizable Parameters

You can override these environment variables when starting the container:

**Security Settings**
- `SECRET_KEY` - Secret key for JWT token signing
- `ALGORITHM` - JWT algorithm (default: HS256)
- `ACCESS_TOKEN_EXPIRE_MINUTES` - Token validity period (default: 30)
- `IDDLE_MINUTES` - Session idle timeout (default: 30)
- `SERVICE_TOKEN` - Inter-service authentication token

**Rate Limiting**
- `RATE_LIMITS_PUBLIC_ROUTES` - Public routes rate limit (default: 100)
- `RATE_LIMITS_PRIVATE_ROUTES` - Private routes rate limit (default: 300)
- `RATE_LIMITS_PUBLIC_TIME_UNIT` - Public time unit (default: 10minute)
- `RATE_LIMITS_PRIVATE_TIME_UNIT` - Private time unit (default: 60minute)

**Example of overriding parameters:**
```bash
SECRET_KEY=my_custom_secret ACCESS_TOKEN_EXPIRE_MINUTES=60 docker-compose up -d
```

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

## License

[Your license information]