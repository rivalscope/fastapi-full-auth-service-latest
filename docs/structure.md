# Login Module Project Structure

```
auth_service/
│
├── .env                          # Environment variables configuration
├── main.py                       # Application entry point
├── requirements.txt              # Python dependencies
│
├── app/                          # Main application package
│   ├── __init__.py               # Package initializer
│   ├── app.py                    # FastAPI application factory
│   │
│   ├── models/                   # Database models
│   │   ├── __init__.py
│   │   └── user.py               # User model definition
│   │
│   ├── routers/                  # API route definitions
│   │   ├── __init__.py
│   │   ├── accounts_recovery.py  # Password recovery with passphrase verification
│   │   ├── admin_accounts_management.py  # Admin-only account management endpoints
│   │   ├── inter_service_token_validation.py  # Service-to-service token verification
│   │   ├── user_account_management.py  # User account self-management endpoints
│   │   ├── users_auth.py         # Authentication endpoints (login, logout)
│   │   └── users_registration.py # User registration endpoints
│   │
│   ├── schemas/                  # Pydantic schemas for request/response validation
│   │   ├── __init__.py
│   │   ├── user.py               # User-related schemas
│   │   └── token.py              # Token-related schemas
│   │
│   └── utils/                    # Utility functions
│       ├── __init__.py           # (if exists)
│       ├── config.py             # Configuration settings
│       ├── security.py           # Security-related utilities (hashing, JWT)
│       ├── logging.py            # Logging configuration and utilities
│       ├── password.py           # Password validation, policies, and management
│       └── db.py     # Database connection and session management
│
├── logs/                         # Log files directory
│   └── logs.db                   # SQLite database for logs
│
└── docs/                         # Documentation
    └── structure.md              # Project structure documentation
```

## Directory Structure Explanation

### Root Directory
- `.env`: Contains environment variables for configuration
- `main.py`: Application entry point that initializes FastAPI app with all routers
- `requirements.txt`: Lists all Python package dependencies

### App Package
- `app.py`: Factory function to create and configure FastAPI application

### Models
- `user.py`: Defines the User database model with SQLAlchemy ORM

### Routers
- `accounts_recovery.py`: Enhanced password reset using robust passphrase verification with space handling
- `admin_accounts_management.py`: Admin-only endpoints to manage user accounts
- `inter_service_token_validation.py`: Endpoints for validating tokens between services
- `user_account_management.py`: Endpoints for users to manage their own accounts
- `users_auth.py`: Authentication endpoints (login, logout)
- `users_registration.py`: User registration endpoint

### Schemas
- `user.py`: Pydantic models for user data validation (creation, updates, output)
- `token.py`: Pydantic models for token data (authentication, verification)

### Utils
- `config.py`: Loads and validates environment variables using Pydantic
- `security.py`: Security utilities (password hashing, JWT token management)
- `logging.py`: Logging configuration with both console and SQLite storage
- `password.py`: Password utility functions for hashing and verification
- `users_database.py`: Handles database connections, session management, and table creation

### Logs
- Storage location for application logs in SQLite database format

### Docs
- Documentation files for the project structure and organization
