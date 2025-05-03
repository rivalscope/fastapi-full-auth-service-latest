---
title: Authentication Service
date: May 2, 2025
author: Vasile Alecu AILaboratories.net
version: 1.1
status: Production Ready
---

# How It Works: Login Module Technical Implementation

This document provides a detailed explanation of the actual implementation of the Login Module.

## Table of Contents
- [Overall Architecture](#overall-architecture)
- [Authentication System](#authentication-system)
- [User Registration](#user-registration)
- [Account Recovery](#account-recovery)
- [User Account Management](#user-account-management)
- [Admin Account Management](#admin-account-management)
- [Inter-Service Token Validation](#inter-service-token-validation)
- [Logging System](#logging-system)
- [Security Implementation](#security-implementation)

## Overall Architecture

The Login Module is implemented as a FastAPI application with a clear separation of concerns:

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
│       ├── security.py           # Security-related utilities (hashing, JWT, bearer token)
│       ├── logging.py            # Logging configuration and utilities
│       ├── password.py           # Password validation, policies, and management
│       ├── password_validation.py# Enforce strong user input for passwords
│       └── db.py                 # Database connection and session management
│
├── logs/                         # Log files directory
│   └── logs.db                   # SQLite database for logs
│
└── docs/                         # Documentation
│   └── structure.md              # Project structure documentation
├── sql_app.db                    # User DB

```

The application entry point (`main.py`) initializes the FastAPI app and includes all routers.

## Authentication System

The authentication system is defined in `app/routers/users_auth.py` and uses several utilities from `app/utils/security.py`.

### Login Endpoint Implementation

```python
@router.post("/login")
@limiter.limit(f"{settings.RATE_LIMITS_PUBLIC_ROUTES}/{settings.RATE_LIMITS_PUBLIC_TIME_UNIT}")
async def login(
    request: Request,
    user_data: UserLogin,
    db: Session = Depends(get_db)
):
    # Log login attempt with email for audit trail
    logger.info(f"Login attempt for email: {user_data.email}")
    
    # Authenticate user credentials against database
    user = authenticate_user(db, user_data.email, user_data.password)
    if not user:
        # Log and respond to failed authentication
        logger.warning(f"Login failed: Invalid credentials for {user_data.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Generate unique secret for this session's JWT
    secret = create_random_secret()
    
    # Prepare user data for token and create JWT
    token_data = {"id": user.id, "nickname": user.nickname, "role": user.role}
    access_token = create_access_token(token_data, secret)
    
    # Update user record with new session information
    user.token = access_token
    user.secret = secret
    user.iddle_time = func.now()
    
    # Save changes to database
    db.commit()
    
    # Log successful authentication
    logger.info(f"User logged in successfully: {user.email}")
    
    # Return token and user information
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user": user
    }
```

### JWT Token Structure

The actual JWT tokens contain the following claims:
- `id`: User ID 
- `nickname`: User's nickname
- `role`: User's role (e.g., "user", "admin")
- `exp`: Expiration timestamp

### Token Validation Implementation

Token validation uses FastAPI's dependency injection system with Bearer authentication:

```python
def extract_token_from_header(authorization: Optional[str] = None):
    """
    Extracts token from the Authorization header
    
    Args:
        authorization: The Authorization header value (Bearer token)
        
    Returns:
        The token string if valid, None otherwise
    """
    if not authorization:
        return None
        
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return None
        
    return token

async def get_current_user(
    auth: str = Security(oauth2_scheme),
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Extract token from Authorization header
    token = extract_token_from_header(auth)
    if not token:
        raise credentials_exception
    
    # Get the user by token
    user = get_user_by_token(db, token)
    if not user:
        raise credentials_exception
    
    # Verify the token using user's secret
    payload = decode_token(token, user.secret)
    if not payload:
        # Invalidate user credentials on token error
        user.token = None
        user.secret = None
        user.iddle_time = None
        db.commit()
        raise credentials_exception
    
    # Verify token belongs to the correct user
    if payload.get("id") != user.id:
        user.token = None
        user.secret = None
        user.iddle_time = None
        db.commit()
        raise credentials_exception
    
    return user
```

### Logout Process

The logout process now uses Bearer authentication to identify the token to invalidate:

```python
@router.post("/logout")
@limiter.limit(f"{settings.RATE_LIMITS_PUBLIC_ROUTES}/{settings.RATE_LIMITS_PUBLIC_TIME_UNIT}")
async def logout(
    request: Request,
    auth: str = Security(oauth2_scheme),
    db: Session = Depends(get_db)
):
    # Log logout attempt
    logger.info("Logout attempt")
    
    # Extract token from Authorization header
    token = extract_token_from_header(auth)
    if not token:
        # Log and respond to missing token
        logger.warning("Logout failed: No token provided")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Find user by token to validate session
    user = db.query(User).filter(User.token == token).first()
    if not user:
        # Log and respond to invalid token
        logger.warning("Logout failed: Invalid token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Clear user session data to invalidate token
    user.token = None
    user.secret = None
    user.iddle_time = None
    
    # Save changes to database
    db.commit()
    
    # Log successful logout
    logger.info(f"User logged out successfully: {user.email}")
    
    # Return success message
    return {"detail": "Logged out successfully"}
```

## User Registration

The registration process is implemented in `app/routers/users_registration.py`.

### Registration Endpoint

```python
@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(
    user_create: UserCreate,
    db: Session = Depends(get_db)
):
    # Check if email already exists
    existing_email = get_user_by_email(db, user_create.email)
    if (existing_email):
        raise HTTPException(400, detail="Email already registered")
    
    # Check if username exists
    existing_username = get_user_by_username(db, user_create.username)
    if (existing_username):
        raise HTTPException(400, detail="Username already taken")
    
    # Validate password against policy
    validate_password(user_create.password)
    
    # Hash password
    hashed_password = get_password_hash(user_create.password)
    
    # Normalize and hash recovery passphrase
    normalized_passphrase = normalize_passphrase(user_create.recovery_passphrase)
    hashed_passphrase = get_password_hash(normalized_passphrase)
    
    # Create new user with UUID
    user_id = uuid.uuid4()
    
    # Prepare user data
    user_data = user_create.dict()
    user_data.pop("password")
    user_data.pop("recovery_passphrase")
    
    # Create user model
    db_user = User(
        id=user_id,
        hashed_password=hashed_password,
        hashed_recovery_passphrase=hashed_passphrase,
        is_active=True,  # or False if email verification is required
        created_at=datetime.utcnow(),
        **user_data
    )
    
    # Add to database
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # Log user creation
    logger.info(f"New user registered: {db_user.id}")
    
    # Send verification email if required
    if settings.REQUIRE_EMAIL_VERIFICATION:
        send_verification_email(db_user.email, create_verification_token(str(db_user.id)))
    
    # Return user data (excluding sensitive information)
    return UserResponse.from_orm(db_user)
```

### Passphrase Normalization

The exact implementation of passphrase normalization:

```python
def normalize_passphrase(passphrase: str) -> str:
    # Convert to lowercase
    normalized = passphrase.lower()
    # Remove leading/trailing spaces
    normalized = normalized.strip()
    # Replace multiple spaces with a single space
    normalized = re.sub(r'\s+', ' ', normalized)
    return normalized
```

## Account Recovery

The account recovery implementation in `app/routers/accounts_recovery.py` uses a multi-step process.

### Step 1: Request Reset

```python
@router.post("/request-reset")
async def request_password_reset(
    email_data: EmailSchema,
    db: Session = Depends(get_db)
):
    # Don't reveal if email exists for security
    user = get_user_by_email(db, email_data.email)
    if user:
        # Log reset request
        logger.info(f"Password reset requested for user {user.id}")
        # Send notification email
        send_reset_notification_email(user.email)
    
    # Always return success to prevent email enumeration
    return {"message": "Recovery instructions sent if email exists"}
```

### Step 2: Verify Passphrase

```python
@router.post("/verify-passphrase")
async def verify_recovery_passphrase(
    recovery_data: PassphraseVerify,
    db: Session = Depends(get_db)
):
    user = get_user_by_email(db, recovery_data.email)
    
    if not user:
        # Use constant time comparison to prevent timing attacks
        verify_password("dummy_passphrase", get_password_hash("dummy_passphrase"))
        raise HTTPException(400, detail="Invalid email or passphrase")
        
    # Normalize the provided passphrase the same way as during registration
    normalized_passphrase = normalize_passphrase(recovery_data.passphrase)
    
    # Verify passphrase
    if not verify_password(normalized_passphrase, user.hashed_recovery_passphrase):
        # Log failed attempt
        logger.warning(f"Failed passphrase verification for user {user.id}")
        raise HTTPException(400, detail="Invalid email or passphrase")
    
    # Generate short-lived reset token (15 minutes)
    reset_token_expires = timedelta(minutes=15)
    reset_token = create_reset_token(
        data={"sub": str(user.id), "type": "password_reset"},
        expires_delta=reset_token_expires
    )
    
    # Log successful verification
    logger.info(f"Successful passphrase verification for user {user.id}")
    
    return {"reset_token": reset_token}
```

### Step 3: Reset Password

```python
@router.post("/reset-password")
async def reset_password(
    reset_data: PasswordReset,
    db: Session = Depends(get_db)
):
    # Validate new password
    validate_password(reset_data.new_password)
    
    # Verify reset token
    try:
        payload = jwt.decode(
            reset_data.reset_token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        
        # Check token type
        if payload.get("type") != "password_reset":
            raise HTTPException(400, detail="Invalid reset token")
            
        user_id = payload.get("sub")
        user = get_user_by_id(db, user_id)
        
        if not user:
            raise HTTPException(400, detail="Invalid reset token")
            
    except JWTError:
        raise HTTPException(400, detail="Invalid or expired reset token")
    
    # Hash the new password
    hashed_password = get_password_hash(reset_data.new_password)
    
    # Update user's password
    user.hashed_password = hashed_password
    user.password_last_changed = datetime.utcnow()
    db.commit()
    
    # Invalidate all existing sessions for this user
    remove_all_user_tokens(db, user.id)
    
    # Log password reset
    logger.info(f"Password reset completed for user {user.id}")
    
    return {"message": "Password successfully reset"}
```

## User Account Management

The user account management implementation in `app/routers/user_account_management.py` now uses Bearer authentication for all operations.

### Profile Management

```python
@router.get("/", response_model=UserAccountDetails)
async def get_account(
    auth: str = Security(oauth2_scheme),
    db: Session = Depends(get_db)
):
    # Extract token from Authorization header
    token = extract_token_from_header(auth)
    if not token:
        # Return unauthorized error if no token provided
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Authenticate user with provided token
    user = get_user_by_token(db, token)
    if not user:
        # Return unauthorized error if token is invalid
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    # Return the authenticated user's account information
    return user
```

### Password Change

```python
@router.put("/change-password")
async def change_password(
    password_change: PasswordChange,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Verify current password
    if not verify_password(password_change.current_password, current_user.hashed_password):
        logger.warning(f"Failed password change attempt for user {current_user.id}")
        raise HTTPException(400, detail="Current password is incorrect")
    
    # Validate new password
    validate_password(password_change.new_password)
    
    # Optional: Check password history to prevent reuse
    if settings.PASSWORD_HISTORY_SIZE > 0:
        if is_password_in_history(current_user.id, password_change.new_password, db):
            raise HTTPException(400, detail="Password has been used previously")
    
    # Hash new password
    hashed_password = get_password_hash(password_change.new_password)
    
    # Update user's password
    current_user.hashed_password = hashed_password
    current_user.password_last_changed = datetime.utcnow()
    
    # Add to password history if enabled
    if settings.PASSWORD_HISTORY_SIZE > 0:
        add_password_to_history(current_user.id, hashed_password, db)
    
    # Commit changes
    db.commit()
    
    # Optionally invalidate other sessions
    if settings.INVALIDATE_SESSIONS_ON_PASSWORD_CHANGE:
        # Keep current session only
        token = get_auth_token_from_request()
        remove_all_user_tokens_except(db, current_user.id, token)
    
    # Send password change notification
    send_password_change_notification(current_user.email)
    
    # Log password change
    logger.info(f"Password changed for user {current_user.id}")
    
    return {"message": "Password successfully changed"}
```

## Admin Account Management

Admin functionality is implemented in `app/routers/admin_accounts_management.py` with Bearer authentication.

### Admin Authentication

```python
async def get_current_admin_user(
    auth: str = Security(oauth2_scheme),
    db: Session = Depends(get_db)
) -> User:
    # Extract token from Authorization header
    token = extract_token_from_header(auth)
    if not token:
        logger.warning("Admin access attempt failed: No token provided")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Authenticate user based on token and verify admin privileges
    user = get_user_by_token(db, token)
    if not user:
        logger.warning("Admin access attempt failed: Invalid token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Ensure user has admin role before granting access
    if user.role != "admin":
        logger.warning(f"Unauthorized admin access attempt by user ID: {user.id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions. Admin role required.",
        )
    return user
```

### List Users Endpoint

```python
@router.get("/users")
async def list_users(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    active: Optional[bool] = None,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    # Calculate offset for pagination
    offset = (page - 1) * limit
    
    # Build filters
    filters = []
    if active is not None:
        filters.append(User.is_active == active)
    
    # Get total count
    total = db.query(User).filter(*filters).count()
    
    # Get users with pagination
    users = db.query(User).filter(*filters).offset(offset).limit(limit).all()
    
    # Log admin action
    logger.info(f"Admin {admin_user.id} listed users (page: {page}, limit: {limit})")
    
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "users": [UserResponse.from_orm(user) for user in users]
    }
```

### User Management Endpoints

```python
@router.get("/users/{user_id}", response_model=UserAdminResponse)
async def get_user(
    user_id: UUID,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    user = get_user_by_id(db, str(user_id))
    if not user:
        raise HTTPException(404, detail="User not found")
        
    # Log admin action
    logger.info(f"Admin {admin_user.id} viewed user {user_id}")
    
    return user

@router.put("/users/{user_id}", response_model=UserAdminResponse)
async def update_user(
    user_id: UUID,
    user_update: UserAdminUpdate,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    user = get_user_by_id(db, str(user_id))
    if not user:
        raise HTTPException(404, detail="User not found")
    
    # Prevent privilege escalation - only superadmins can create new admins
    if (user_update.is_admin is True and 
        not user.is_admin and 
        not admin_user.is_superadmin):
        raise HTTPException(403, detail="Only superadmins can grant admin privileges")
    
    # Update user fields
    for field, value in user_update.dict(exclude_unset=True).items():
        setattr(user, field, value)
    
    user.updated_at = datetime.utcnow()
    
    # Commit changes
    db.commit()
    db.refresh(user)
    
    # Log admin action
    logger.info(f"Admin {admin_user.id} updated user {user_id}")
    
    return user

@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: UUID,
    permanent: bool = Query(False),
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    user = get_user_by_id(db, str(user_id))
    if not user:
        raise HTTPException(404, detail="User not found")
    
    # Prevent deleting superadmins
    if user.is_superadmin and not admin_user.is_superadmin:
        raise HTTPException(403, detail="Only superadmins can delete superadmin accounts")
    
    if permanent:
        # Only superadmins can permanently delete
        if not admin_user.is_superadmin:
            raise HTTPException(403, detail="Only superadmins can permanently delete accounts")
            
        # Hard delete
        db.delete(user)
        logger.warning(f"Admin {admin_user.id} permanently deleted user {user_id}")
    else:
        # Soft delete - just mark as inactive
        user.is_active = False
        user.deactivated_at = datetime.utcnow()
        user.deactivated_by = str(admin_user.id)
        logger.info(f"Admin {admin_user.id} deactivated user {user_id}")
    
    db.commit()
    
    return None
```

## Inter-Service Token Validation

The service-to-service authentication is implemented in `app/routers/inter_service_token_validation.py` and now uses dual authentication with both Bearer token and X-Service-Token headers.

### Security Schemes

```python
# Define security schemes for OpenAPI docs
oauth2_scheme = HTTPBearer(
    scheme_name="userAuth",
    description="Short-lived opaque key the browser holds",
    bearerFormat="OPAQUE",
    auto_error=False
)

api_key_header = APIKeyHeader(
    name="X-Service-Token", 
    scheme_name="serviceAuth",
    description="Internal service secret",
    auto_error=False
)
```

### Token Validation

```python
@router.post(
    "/verify", 
    response_model=TokenVerifyResponse,
    openapi_extra={
        "security": [{"userAuth": [], "serviceAuth": []}]
    }
)
@limiter.limit(f"{settings.RATE_LIMITS_PRIVATE_ROUTES}/{settings.RATE_LIMITS_PRIVATE_TIME_UNIT}")
async def verify_token(
    request: Request,
    auth: str = Security(oauth2_scheme),
    service_token: str = Security(api_key_header),
    db: Session = Depends(get_db)
):
    # Log verification request for audit trail
    logger.info("Token verification request received")
    
    # Extract user token from Authorization header
    user_token = extract_token_from_header(auth)
    if not user_token:
        logger.warning("Token verification failed: No user token provided")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found"
        )
    
    # Verify service token to ensure request comes from authorized service
    if not verify_service_token(service_token):
        logger.warning("Token verification failed: Invalid service token")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found"
        )
    
    # Look up the user by their token in the database
    user = db.query(User).filter(User.token == user_token).first()
    if not user:
        logger.warning("Token verification failed: User token not found")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found"
        )
    
    # Return user information to the requesting service
    return TokenVerifyResponse(id=user.id, email=user.email, nickname=user.nickname, role=user.role, lock=user.lock, customer_account=user.customer_account)
```

## Logging System

The logging implementation in `app/utils/logging.py` handles structured logging to both console and database.

### Logger Configuration

```python
def setup_logging():
    # Create formatters
    json_formatter = jsonlogger.JsonFormatter(
        '%(timestamp)s %(level)s %(name)s %(message)s %(user_id)s %(request_id)s %(ip)s',
        rename_fields={
            'levelname': 'level',
            'asctime': 'timestamp'
        }
    )
    
    # Create handlers
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(json_formatter)
    
    # Create SQLite handler if enabled
    if settings.LOG_TO_DB:
        db_handler = SQLiteHandler('logs/logs.db')
        db_handler.setFormatter(json_formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(settings.LOG_LEVEL)
    root_logger.addHandler(console_handler)
    
    if settings.LOG_TO_DB:
        root_logger.addHandler(db_handler)
    
    # Return the configured logger
    return logging.getLogger("login_module")
```

### SQLite Logging Handler

```python
class SQLiteHandler(logging.Handler):
    def __init__(self, db_path):
        logging.Handler.__init__(self)
        self.db_path = db_path
        self._create_table()
    
    def _create_table(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            level TEXT,
            name TEXT,
            message TEXT,
            user_id TEXT,
            request_id TEXT,
            ip TEXT,
            additional_data TEXT
        )
        ''')
        conn.commit()
        conn.close()
    
    def emit(self, record):
        # Extract log information
        log_entry = self.format(record)
        log_dict = json.loads(log_entry)
        
        # Extract standard fields
        timestamp = log_dict.pop('timestamp', datetime.utcnow().isoformat())
        level = log_dict.pop('level', record.levelname)
        name = log_dict.pop('name', record.name)
        message = log_dict.pop('message', record.getMessage())
        user_id = log_dict.pop('user_id', None)
        request_id = log_dict.pop('request_id', None)
        ip = log_dict.pop('ip', None)
        
        # Any remaining fields go into additional_data
        additional_data = json.dumps(log_dict) if log_dict else None
        
        # Insert into database
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO logs 
                (timestamp, level, name, message, user_id, request_id, ip, additional_data) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (timestamp, level, name, message, user_id, request_id, ip, additional_data)
            )
            conn.commit()
        except Exception as e:
            sys.stderr.write(f"Error writing to log database: {e}\n")
        finally:
            if conn:
                conn.close()
```

## Security Implementation

Security features are implemented throughout the application, with core functionality in `app/utils/security.py`.

### Password Hashing

```python
def get_password_hash(password: str) -> str:
    # Generate a salt and hash the password
    salt = bcrypt.gensalt(rounds=12)
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password.decode()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Verify a password against a hash
    return bcrypt.checkpw(
        plain_password.encode(),
        hashed_password.encode()
    )
```

### JWT Token Functions

```python
def create_access_token(data: dict, expires_delta: timedelta = None) -> str:
    to_encode = data.copy()
    
    # Set expiration
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
        
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    to_encode.update({"type": "access_token"})
    
    # Encode the JWT
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    
    return encoded_jwt
```

### Authentication Headers

Authentication is now handled using standard HTTP headers following these patterns:

1. **User Authentication with Bearer Token**
   ```
   Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   ```
   This header is used for all protected endpoints that require user authentication.

2. **Service-to-Service Authentication with Dual Headers**
   ```
   Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   X-Service-Token: SERVICE_SECRET_TOKEN
   ```
   This combination is used only for the token verification endpoint which requires both types of authentication.

3. **OpenAPI Security Schemes**

   The API defines two security schemes in the OpenAPI specification:
   
   ```json
   {
     "components": {
       "securitySchemes": {
         "userAuth": {
           "type": "http",
           "scheme": "bearer",
           "bearerFormat": "OPAQUE"
         },
         "serviceAuth": {
           "type": "apiKey",
           "in": "header",
           "name": "X-Service-Token"
         }
       }
     }
   }
   ```

   These schemes are applied globally or at the individual endpoint level to define the security requirements.

### Password Validation

```python
def validate_password(password: str) -> bool:
    # Check minimum length
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        raise ValueError(f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters long")
    
    # Check for complexity if required
    if settings.PASSWORD_COMPLEXITY_CHECK:
        # Check for lowercase
        if not any(c.islower() for c in password):
            raise ValueError("Password must contain at least one lowercase letter")
            
        # Check for uppercase
        if not any(c.isupper() for c in password):
            raise ValueError("Password must contain at least one uppercase letter")
            
        # Check for digit
        if not any(c.isdigit() for c in password):
            raise ValueError("Password must contain at least one digit")
            
        # Check for special character
        if not any(c in settings.SPECIAL_CHARACTERS for c in password):
            raise ValueError("Password must contain at least one special character")
    
    # Check common password list if enabled
    if settings.CHECK_COMMON_PASSWORDS and is_common_password(password):
        raise ValueError("This password is too common and easily guessed")
    
    return True
```

### Rate Limiting Implementation

```python
class RateLimiter:
    def __init__(self, max_attempts: int, time_window: int):
        self.max_attempts = max_attempts
        self.time_window = time_window  # in seconds
        self.attempts = {}
    
    def check_rate_limit(self, key: str) -> bool:
        """Check if a key has exceeded the rate limit"""
        current_time = time.time()
        
        # Clean up old entries
        self._cleanup(current_time)
        
        # Get attempts for this key
        key_attempts = self.attempts.get(key, [])
        
        # Count recent attempts within time window
        recent_attempts = [t for t in key_attempts if t > current_time - self.time_window]
        
        # Check if limit exceeded
        if len(recent_attempts) >= self.max_attempts:
            return False
        
        # Record this attempt
        recent_attempts.append(current_time)
        self.attempts[key] = recent_attempts
        
        return True
    
    def _cleanup(self, current_time: float):
        """Remove attempts older than the time window"""
        keys_to_remove = []
        
        for key, timestamps in self.attempts.items():
            valid_timestamps = [t for t in timestamps if t > current_time - self.time_window]
            if valid_timestamps:
                self.attempts[key] = valid_timestamps
            else:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.attempts[key]
```

This implementation matches the actual behavior and code structure of the login module, providing an accurate "like for like" description of how the system works.
