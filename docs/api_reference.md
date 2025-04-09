# API Reference

This document provides details for all API endpoints available in the Login Module.

## Table of Contents
- [Authentication](#authentication)
- [User Registration](#user-registration)
- [Account Recovery](#account-recovery)
- [User Account Management](#user-account-management)
- [Admin Account Management](#admin-account-management)
- [Inter-Service Token Validation](#inter-service-token-validation)

## Authentication

### Login
**Endpoint**: `POST /auth/login`

Authenticates a user and returns a JWT token.

**Request Body**:
```json
{
  "username": "user@example.com",
  "password": "securepassword"
}
```

**Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

### Logout
**Endpoint**: `POST /auth/logout`

Invalidates the current user's token.

**Headers**:
- `Authorization: Bearer {token}`

**Response** (200 OK):
```json
{
  "message": "Successfully logged out"
}
```

## User Registration

### Register New User
**Endpoint**: `POST /users/register`

Creates a new user account.

**Request Body**:
```json
{
  "email": "user@example.com",
  "username": "johndoe",
  "password": "SecurePassword123!",
  "full_name": "John Doe",
  "recovery_passphrase": "four words as passphrase"
}
```

**Response** (201 Created):
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "user@example.com",
  "username": "johndoe",
  "full_name": "John Doe",
  "is_active": true,
  "created_at": "2023-01-01T12:00:00Z"
}
```

## Account Recovery

### Request Password Reset
**Endpoint**: `POST /recovery/request-reset`

Initiates the password recovery process.

**Request Body**:
```json
{
  "email": "user@example.com"
}
```

**Response** (200 OK):
```json
{
  "message": "Recovery instructions sent if email exists"
}
```

### Verify Passphrase
**Endpoint**: `POST /recovery/verify-passphrase`

Verifies the recovery passphrase.

**Request Body**:
```json
{
  "email": "user@example.com",
  "passphrase": "four words as passphrase"
}
```

**Response** (200 OK):
```json
{
  "reset_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### Reset Password
**Endpoint**: `POST /recovery/reset-password`

Resets the user's password using a valid reset token.

**Request Body**:
```json
{
  "reset_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "new_password": "NewSecurePassword123!"
}
```

**Response** (200 OK):
```json
{
  "message": "Password successfully reset"
}
```

## User Account Management

### Get Current User Profile
**Endpoint**: `GET /account/profile`

Returns the current user's profile information.

**Headers**:
- `Authorization: Bearer {token}`

**Response** (200 OK):
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "user@example.com",
  "username": "johndoe",
  "full_name": "John Doe",
  "is_active": true,
  "created_at": "2023-01-01T12:00:00Z"
}
```

### Update User Profile
**Endpoint**: `PUT /account/profile`

Updates the current user's profile information.

**Headers**:
- `Authorization: Bearer {token}`

**Request Body**:
```json
{
  "full_name": "John M. Doe",
  "username": "john_doe" 
}
```

**Response** (200 OK):
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "user@example.com",
  "username": "john_doe",
  "full_name": "John M. Doe",
  "is_active": true,
  "created_at": "2023-01-01T12:00:00Z",
  "updated_at": "2023-01-02T12:00:00Z"
}
```

### Change Password
**Endpoint**: `PUT /account/change-password`

Changes the current user's password.

**Headers**:
- `Authorization: Bearer {token}`

**Request Body**:
```json
{
  "current_password": "CurrentPassword123!",
  "new_password": "NewPassword456!"
}
```

**Response** (200 OK):
```json
{
  "message": "Password successfully changed"
}
```

## Admin Account Management

### List All Users
**Endpoint**: `GET /admin/users`

Returns a list of all users (admin only).

**Headers**:
- `Authorization: Bearer {admin_token}`

**Query Parameters**:
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 50)
- `active`: Filter by active status (optional)

**Response** (200 OK):
```json
{
  "total": 100,
  "page": 1,
  "limit": 50,
  "users": [
    {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "email": "user@example.com",
      "username": "johndoe",
      "full_name": "John Doe",
      "is_active": true,
      "created_at": "2023-01-01T12:00:00Z"
    },
    // More users...
  ]
}
```

### Get User by ID
**Endpoint**: `GET /admin/users/{user_id}`

Returns a specific user by ID (admin only).

**Headers**:
- `Authorization: Bearer {admin_token}`

**Response** (200 OK):
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "user@example.com",
  "username": "johndoe",
  "full_name": "John Doe",
  "is_active": true,
  "created_at": "2023-01-01T12:00:00Z",
  "last_login": "2023-01-05T14:30:00Z"
}
```

### Update User (Admin)
**Endpoint**: `PUT /admin/users/{user_id}`

Updates a user's information (admin only).

**Headers**:
- `Authorization: Bearer {admin_token}`

**Request Body**:
```json
{
  "is_active": false,
  "is_admin": false,
  "full_name": "John M. Doe"
}
```

**Response** (200 OK):
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "user@example.com",
  "username": "johndoe",
  "full_name": "John M. Doe",
  "is_active": false,
  "is_admin": false,
  "created_at": "2023-01-01T12:00:00Z",
  "updated_at": "2023-01-10T09:15:00Z"
}
```

### Delete User
**Endpoint**: `DELETE /admin/users/{user_id}`

Deletes a user (admin only).

**Headers**:
- `Authorization: Bearer {admin_token}`

**Response** (204 No Content)

## Inter-Service Token Validation

### Validate Token
**Endpoint**: `POST /service/validate-token`

Validates a JWT token for inter-service communication.

**Request Body**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "service_id": "inventory-service"
}
```

**Response** (200 OK):
```json
{
  "valid": true,
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "scopes": ["read:inventory", "write:inventory"]
}
```

### Generate Service Token
**Endpoint**: `POST /service/token`

Generates a service-to-service token.

**Headers**:
- `Authorization: Bearer {admin_token}`

**Request Body**:
```json
{
  "service_id": "reporting-service",
  "scopes": ["read:users", "read:logs"],
  "expires_in": 3600
}
```

**Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "service_id": "reporting-service"
}
```
