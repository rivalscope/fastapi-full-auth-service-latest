---
title: User Login Status Tracking
date: May 3, 2025
author: Vasile Alecu AILaboratories.net
version: 1.0
status: Production Ready
---

# User Login Status Tracking Implementation

## Overview

This feature tracks whether users are actively logged in by monitoring their idle time. It enables administrators to see which users are currently active when viewing user data through the admin API.

## Configuration Parameters

The feature uses two configurable time thresholds:

- `IDDLE_MINUTES=15`: Time in minutes before a user is considered idle
- `ACCESS_TOKEN_EXPIRE_MINUTES=30`: Time in minutes before a session is completely expired

## Implementation Details

### 1. Database Model Changes

Added a new `is_logged_in` boolean field to the User model in `app/models/users_table.py`:

```python
class User(Base):
    __tablename__ = "users"
    # ...existing user fields...
    is_logged_in = Column(Boolean, default=False)  # User's login status, True if currently logged in
```

This field indicates whether a user is currently logged in to the system.

### 2. Authentication Flow Updates

#### Login Process

Modified the login handler in `app/routers/users_auth.py` to set the `is_logged_in` flag to `True` when a user logs in:

```python
# Update user record with new session information
user.token = access_token
user.secret = secret
user.iddle_time = func.now()
user.is_logged_in = True  # Set login status to True
```

#### Logout Process

Updated the logout handler in `app/routers/users_auth.py` to set the `is_logged_in` flag to `False` when a user logs out:

```python
# Clear user session data to invalidate token
user.token = None
user.secret = None
user.iddle_time = None
user.is_logged_in = False  # Set login status to False
```

### 3. Active Status Detection

Added a new utility function `is_user_active()` in `app/utils/security.py` that checks if a user is actively logged in:

```python
def is_user_active(user, update_status=True, db=None):
    """
    Checks if a user is actively logged in based on idle time and token status
    
    Args:
        user: User object to check
        update_status: Whether to update the is_logged_in status if expired (default: True)
        db: Database session, required if update_status=True
        
    Returns:
        Boolean indicating if the user is actively logged in
    """
    if not user.is_logged_in or not user.token or not user.iddle_time:
        return False
    
    # Calculate session timeout based on idle time
    now = datetime.utcnow()
    idle_timeout = timedelta(minutes=settings.IDDLE_MINUTES)
    token_timeout = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Check if the user's idle time exceeds the configured threshold
    idle_expired = user.iddle_time + idle_timeout < now
    token_expired = user.iddle_time + token_timeout < now
    
    if idle_expired or token_expired:
        if update_status and db:
            # Update the user's login status if expired
            user.is_logged_in = False
            db.commit()
            logger.info(f"User {user.id} session marked as expired due to inactivity")
        return False
    
    return True
```

### 4. Schema Updates

Updated the `UserInDB` Pydantic schema in `app/schemas/user.py` to include the new `is_logged_in` field:

```python
class UserInDB(UserBase):
    id: int
    role: str
    lock: bool
    iddle_time: Optional[datetime] = None
    is_logged_in: bool = False
    
    model_config = {
        "from_attributes": True
    }
```

### 5. Admin API Integration

Updated the admin user management endpoints in `app/routers/admin_accounts_management.py` to check and update user active status:

#### Single User Details

```python
@router.get("/{user_id}", response_model=UserInDB)
async def get_user_details(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
):
    # ...existing code...
    
    # Check if user is active based on idle time
    is_user_active(user, update_status=True, db=db)
    
    # ...existing code...
```

#### User List

```python
@router.get("/", response_model=List[UserInDB])
async def list_all_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user),
):
    # ...existing code...
    
    # Check and update active status for each user based on idle time
    for user in users:
        is_user_active(user, update_status=True, db=db)
    
    # ...existing code...
```

## How It Works

1. When a user logs in, the `is_logged_in` flag is set to `True`
2. The `iddle_time` timestamp is updated whenever the user performs authenticated actions
3. When an admin views user information, our system:
   - Checks if the user has `is_logged_in = True`
   - Verifies if the user has a valid token
   - Confirms if the user's `iddle_time` is within the configured thresholds:
     - Within `IDDLE_MINUTES` (15 minutes) to be considered actively using the system
     - Within `ACCESS_TOKEN_EXPIRE_MINUTES` (30 minutes) for the session to still be valid
4. If these conditions aren't met, `is_logged_in` is automatically set to `False`

## Benefits

This implementation provides administrators with real-time visibility into which users are currently active in the system, improving user management and monitoring capabilities.

### Idle Time Display

The admin API now shows a human-readable representation of idle time, making it easier to understand how long a user has been inactive:

- For users idle less than a minute: "X sec" (e.g., "45 sec")
- For users idle for longer periods: "X min Y sec" (e.g., "5 min 30 sec")

This format is automatically generated when user data is returned by the admin API endpoints, replacing the raw timestamp format that was difficult to interpret.

## Potential Future Enhancements

1. Add an API endpoint that shows all currently active users
2. Implement a dashboard widget showing active user count and details
3. Add configurable idle timeout warnings to the frontend
4. Create hooks to notify other services when users become active or inactive