---
title: Authentication Service
date: April 17, 2025
author: Vasile Alecu AILaboratories.net
version: 1.0
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
uth_service/
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
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    # Find user by username/email
    user = get_user_by_username(db, form_data.username)
    if not user:
        # Also try by email
        user = get_user_by_email(db, form_data.username)
        
    # Verify user exists and password is correct
    if not user or not verify_password(form_data.password, user.hashed_password):
        # Log failed attempt
        logger.warning(f"Failed login attempt for username: {form_data.username}")
        raise HTTPException(401, detail="Incorrect username or password")
        
    # Check if user is active
    if not user.is_active:
        raise HTTPException(401, detail="Account is disabled")
        
    # Create access token with 30-minute expiration
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)}, 
        expires_delta=access_token_expires
    )
    
    # Log successful login
    logger.info(f"User {user.id} logged in successfully")
    
    # Store token in database for active session tracking
    store_active_token(db, user.id, access_token)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }
```

### JWT Token Structure

The actual JWT tokens contain the following claims:
- `sub`: User ID (UUID string)
- `exp`: Expiration timestamp
- `iat`: Issued at timestamp
- `type`: Token type ("access_token")
- `roles`: Array of user roles (e.g., ["user", "admin"])

Example JWT payload:
```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "exp": 1616963696,
  "iat": 1616961896,
  "type": "access_token",
  "roles": ["user"]
}
```

### Token Validation Implementation

Token validation uses FastAPI's dependency injection system:

```python
def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        # Decode JWT token
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        user_id: str = payload.get("sub")
        
        if user_id is None:
            raise credentials_exception
            
        # Check if token is in active sessions
        if not is_token_active(db, user_id, token):
            raise credentials_exception
            
    except JWTError:
        raise credentials_exception
        
    # Get user from database
    user = get_user_by_id(db, user_id)
    if user is None or not user.is_active:
        raise credentials_exception
        
    return user
```

### Logout Process

Unlike using a token blacklist, the system actually maintains active sessions in the database:

```python
@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user),
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    # Remove token from active sessions
    remove_active_token(db, current_user.id, token)
    
    # Log logout
    logger.info(f"User {current_user.id} logged out")
    
    return {"message": "Successfully logged out"}
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
    if existing_email:
        raise HTTPException(400, detail="Email already registered")
    
    # Check if username exists
    existing_username = get_user_by_username(db, user_create.username)
    if existing_username:
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

User self-service functionality is implemented in `app/routers/user_account_management.py`.

### Profile Management

```python
@router.get("/profile", response_model=UserResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    return current_user

@router.put("/profile", response_model=UserResponse)
async def update_user_profile(
    profile_update: UserProfileUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Check if username update is requested and it's different
    if (profile_update.username is not None and 
        profile_update.username != current_user.username):
        # Check if new username is available
        existing_user = get_user_by_username(db, profile_update.username)
        if existing_user:
            raise HTTPException(400, detail="Username already taken")
        
        current_user.username = profile_update.username
    
    # Update any provided fields
    for field, value in profile_update.dict(exclude_unset=True).items():
        if field != "username":  # Already handled above
            setattr(current_user, field, value)
    
    # Update modified timestamp
    current_user.updated_at = datetime.utcnow()
    
    # Commit changes
    db.commit()
    db.refresh(current_user)
    
    # Log profile update
    logger.info(f"Profile updated for user {current_user.id}")
    
    return current_user
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

Admin functionality is implemented in `app/routers/admin_accounts_management.py`.

### Admin Authentication

```python
def get_admin_user(
    current_user: User = Depends(get_current_user)
):
    if not current_user.is_admin:
        logger.warning(f"Unauthorized admin access attempt by user {current_user.id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized for admin operations"
        )
    return current_user
```

### List Users Endpoint

```python
@router.get("/users")
async def list_users(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    active: Optional[bool] = None,
    admin_user: User = Depends(get_admin_user),
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
    admin_user: User = Depends(get_admin_user),
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
    admin_user: User = Depends(get_admin_user),
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
    admin_user: User = Depends(get_admin_user),
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

The service-to-service authentication is implemented in `app/routers/inter_service_token_validation.py`.

### Token Validation

```python
@router.post("/validate-token")
async def validate_token(
    validation_request: TokenValidationRequest,
    db: Session = Depends(get_db),
    service_auth: ServiceAuth = Depends(get_service_auth)
):
    # Verify the requesting service is authorized
    if service_auth.service_id != validation_request.service_id:
        logger.warning(f"Service ID mismatch in token validation: {service_auth.service_id} vs {validation_request.service_id}")
        raise HTTPException(403, detail="Service authentication mismatch")
    
    try:
        # Decode and verify the token
        payload = jwt.decode(
            validation_request.token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        
        user_id = payload.get("sub")
        token_type = payload.get("type", "access_token")
        
        # Only validate user tokens
        if token_type != "access_token":
            raise HTTPException(400, detail="Invalid token type")
        
        # Check if token is in active sessions
        if not is_token_active(db, user_id, validation_request.token):
            raise HTTPException(401, detail="Token is invalid or expired")
        
        # Get user info
        user = get_user_by_id(db, user_id)
        if not user or not user.is_active:
            raise HTTPException(401, detail="User account is disabled")
        
        # Get user's scopes for the requesting service
        scopes = get_user_service_scopes(user.id, validation_request.service_id, db)
        
        # Log validation
        logger.info(f"Token validated for user {user_id} by service {validation_request.service_id}")
        
        return {
            "valid": True,
            "user_id": user_id,
            "username": user.username,
            "scopes": scopes
        }
        
    except JWTError:
        logger.warning(f"Invalid token validation attempt by service {validation_request.service_id}")
        raise HTTPException(401, detail="Invalid token")
```

### Service Token Generation

```python
@router.post("/token")
async def generate_service_token(
    token_request: ServiceTokenRequest,
    admin_user: User = Depends(get_admin_user),
    db: Session = Depends(get_db)
):
    # Verify service exists
    service = get_service_by_id(db, token_request.service_id)
    if not service:
        raise HTTPException(404, detail="Service not found")
    
    # Verify requested scopes are valid for this service
    for scope in token_request.scopes:
        if scope not in service.available_scopes:
            raise HTTPException(400, detail=f"Invalid scope: {scope}")
    
    # Create service token
    expires_delta = timedelta(seconds=token_request.expires_in)
    access_token = create_service_token(
        data={
            "sub": token_request.service_id,
            "type": "service_token",
            "scopes": token_request.scopes
        },
        expires_delta=expires_delta
    )
    
    # Log token generation
    logger.info(f"Service token generated for {token_request.service_id} by admin {admin_user.id}")
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": token_request.expires_in,
        "service_id": token_request.service_id
    }
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
