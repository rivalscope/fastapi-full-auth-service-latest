---
title: Authentication Service
date: April 17, 2025
author: Vasile Alecu AILaboratories.net
version: 1.0
status: Production Ready
---

# Auth Service Documentation

## Overview
The Auth Service is a comprehensive authentication and user management service built with FastAPI. It provides secure authentication, user registration, account management, logging, and inter-service token validation capabilities.

## Features
- User registration with email verification
- Secure authentication with JWT tokens
- Password recovery with passphrase verification
- User account self-management
- Admin account management capabilities
- Inter-service token validation
- Comprehensive logging and security features

## Documentation Index
- [API Reference](./api_reference.md) - Detailed API endpoint documentation
- [Project Structure](./structure.md) - Overview of project organization
- [Docker Setup](./docker_app.md) - Detailed Docker configuration documentation

## Getting Started

### Standard Setup

To run this project directly on your machine, follow these steps:

Install dependencies
In your terminal, run:
pip install -r requirements.txt

Set up environment variables
Rename .env.example to .env and adjust values if needed:

Start the FastAPI server
Run the main application using:
from windows: python main.py
from linux/mac: python3 main.py 

This will start the FastAPI server on http://0.0.0.0:8000.
You can now access the API and interactive docs at http://localhost:8000/docs.

### Docker Setup

To run the application using Docker, follow these steps:

1. **Build the Docker image**
   ```bash
   docker-compose build
   ```

2. **Start the containerized application**
   ```bash
   docker-compose up -d
   ```
   The application will be available at http://localhost:8400/docs.

3. **View application logs**
   ```bash
   docker-compose logs -f auth_service
   ```

4. **Stop the containerized application**
   ```bash
   docker-compose down
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

For more details about the Docker setup, see the [Docker documentation](./docker_app.md).

The entry point is main.py.
The server uses Uvicorn and auto-reloads on code changes.

