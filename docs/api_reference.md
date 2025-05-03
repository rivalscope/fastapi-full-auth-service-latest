---
title: Authentication Service
date: May 2, 2025
author: Vasile Alecu AILaboratories.net
version: 1.1
status: Production Ready
---

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
**Endpoint**: `POST /login`

Authenticates a user and returns a JWT token.

**Security**: None (Public endpoint)

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "securepassword"
}
```

**Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "nickname": "johndoe",
    "email": "user@example.com"
  }
}
```

### Logout
**Endpoint**: `POST /logout`

Invalidates the current user's token.

**Security**: Bearer Authentication

**Headers**:
- `Authorization`: Bearer token (e.g., `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`)

**Response** (200 OK):
```json
{
  "detail": "Logged out successfully"
}
```

## User Registration

### Register New User
**Endpoint**: `POST /register`

Creates a new user account.

**Security**: None (Public endpoint)

**Request Body**:
```json
{
  "email": "user@example.com",
  "nickname": "johndoe",
  "password": "SecurePassword123!",
  "customer_account": "none",
  "passphrase": "four words as passphrase"
}
```

**Response** (201 Created):
```json
{
  "id": 1,
  "nickname": "johndoe",
  "email": "user@example.com"
}
```

## Account Recovery

### Recover Password
**Endpoint**: `POST /recovery`

Resets the user's password using their email and passphrase.

**Security**: None (Public endpoint)

**Request Body**:
```json
{
  "email": "user@example.com",
  "passphrase": "four words as passphrase",
  "new_password": "NewSecurePassword123!"
}
```

**Response** (200 OK):
```json
{
  "message": "Password changed successfully"
}
```

## User Account Management

### Get Current User Profile
**Endpoint**: `GET /my_account/`

Returns the current user's profile information.

**Security**: Bearer Authentication

**Headers**:
- `Authorization`: Bearer token (e.g., `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`)

**Response** (200 OK):
```json
{
  "nickname": "johndoe",
  "email": "user@example.com",
  "customer_account": "none",
  "passphrase": "four words as passphrase"
}
```

### Update User Profile
**Endpoint**: `PUT /my_account/`

Updates the current user's profile information.

**Security**: Bearer Authentication

**Headers**:
- `Authorization`: Bearer token (e.g., `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`)

**Request Body**:
```json
{
  "nickname": "john_doe",
  "email": "new_email@example.com",
  "password": "NewPassword123!",
  "customer_account": "premium",
  "passphrase": "new passphrase words here"
}
```

**Response** (200 OK):
```json
{
  "message": "Account details updated successfully"
}
```

### Delete User Account
**Endpoint**: `DELETE /my_account/delete`

Deletes the current user's account.

**Security**: Bearer Authentication

**Headers**:
- `Authorization`: Bearer token (e.g., `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`)

**Response** (200 OK):
```json
{
  "detail": "Account deleted successfully"
}
```

## Admin Account Management

### List All Users
**Endpoint**: `GET /accounts_management/`

Returns a list of all users (admin only).

**Security**: Bearer Authentication

**Headers**:
- `Authorization`: Bearer token (e.g., `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`)

**Query Parameters**:
- `skip`: Number of records to skip (default: 0)
- `limit`: Maximum number of records to return (default: 100)

**Response** (200 OK):
```json
[
  {
    "nickname": "johndoe",
    "email": "user@example.com",
    "customer_account": "none",
    "passphrase": "four words as passphrase",
    "id": 1,
    "role": "user",
    "lock": false,
    "iddle_time": "2023-01-01T12:00:00Z"
  },
  // More users...
]
```

### Create New User
**Endpoint**: `POST /accounts_management/`

Creates a new user account (admin only).

**Security**: Bearer Authentication

**Headers**:
- `Authorization`: Bearer token (e.g., `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`)

**Request Body**:
```json
{
  "nickname": "newuser",
  "email": "newuser@example.com",
  "password": "SecurePassword123!",
  "customer_account": "none",
  "passphrase": "four words as passphrase"
}
```

**Response** (201 Created):
```json
{
  "nickname": "newuser",
  "email": "newuser@example.com",
  "customer_account": "none",
  "passphrase": "four words as passphrase",
  "id": 2,
  "role": "user",
  "lock": false,
  "iddle_time": "2023-01-01T12:00:00Z"
}
```

### Get User by ID
**Endpoint**: `GET /accounts_management/{user_id}`

Returns a specific user by ID (admin only).

**Security**: Bearer Authentication

**Headers**:
- `Authorization`: Bearer token (e.g., `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`)

**Response** (200 OK):
```json
{
  "nickname": "johndoe",
  "email": "user@example.com",
  "customer_account": "none",
  "passphrase": "four words as passphrase",
  "id": 1,
  "role": "user",
  "lock": false,
  "iddle_time": "2023-01-01T12:00:00Z"
}
```

### Update User (Admin)
**Endpoint**: `PUT /accounts_management/{user_id}`

Updates a user's information (admin only).

**Security**: Bearer Authentication

**Headers**:
- `Authorization`: Bearer token (e.g., `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`)

**Request Body**:
```json
{
  "nickname": "updated_name",
  "email": "updated@example.com",
  "password": "NewPassword123!",
  "customer_account": "premium",
  "passphrase": "new passphrase words",
  "role": "user",
  "lock": false
}
```

**Response** (200 OK):
```json
{
  "message": "User details successfully updated for user 1"
}
```

### Delete User
**Endpoint**: `DELETE /accounts_management/{user_id}`

Deletes a user (admin only).

**Security**: Bearer Authentication

**Headers**:
- `Authorization`: Bearer token (e.g., `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`)

**Response** (200 OK):
```json
{
  "message": "User 1 has been successfully deleted"
}
```

## Inter-Service Token Validation

### Validate Token
**Endpoint**: `POST /verify`

Validates a JWT token for inter-service communication.

**Security**: Dual Authentication (both required)
- Bearer Authentication 
- API Key Authentication

**Headers**:
- `Authorization`: Bearer token (e.g., `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...`)
- `X-Service-Token`: Service authentication token

**Response** (200 OK):
```json
{
  "id": 1,
  "email": "user@example.com",
  "nickname": "johndoe",
  "role": "user",
  "valid": true,
  "lock": false,
  "customer_account": "none"
}
```

## Root Endpoint

### Root
**Endpoint**: `GET /`

Returns a welcome message.

**Security**: None (Public endpoint)

**Response** (200 OK):
```json
{
  "message": "Welcome to the FastAPI Auth System"
}
```
