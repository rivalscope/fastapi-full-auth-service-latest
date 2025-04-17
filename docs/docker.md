---
title: Authentication Service
date: April 17, 2025
author: Vasile Alecu AILaboratories.net
version: 1.0
status: Production Ready
---

# Dockerization of FastAPI Authentication Service

This document explains how the FastAPI authentication service has been dockerized, including container setup, environment variable configuration, database persistence, and deployment strategies.

## Table of Contents

- [Overview](#overview)
- [Docker Components](#docker-components)
  - [Dockerfile](#dockerfile)
  - [Docker Compose](#docker-compose)
- [Environment Variables](#environment-variables)
  - [Priority Order](#priority-order)
  - [Available Configuration Options](#available-configuration-options)
- [Data Persistence](#data-persistence)
  - [Database Files](#database-files)
  - [Volume Mapping](#volume-mapping)
- [Running the Containerized Application](#running-the-containerized-application)
  - [Basic Deployment](#basic-deployment)
  - [Runtime Configuration](#runtime-configuration)
  - [Container Management](#container-management)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Database Backup](#database-backup)

## Overview

The FastAPI authentication service has been containerized to ensure consistent deployment across different environments, simplified setup, and proper isolation of the application. The containerization uses Docker and Docker Compose for orchestration.

## Docker Components

### Dockerfile

The `Dockerfile` at the project root defines how the application's container image is built:

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create a non-root user and switch to it
RUN adduser --disabled-password --gecos '' appuser
RUN chown -R appuser:appuser /app
USER appuser

# Expose the application port
EXPOSE 8000

# Command to run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

Key aspects of the Dockerfile:
- Uses Python 3.12 slim image for a smaller footprint
- Installs dependencies before copying code for better layer caching
- Creates and uses a non-root user for security
- Exposes port 8000 for the FastAPI application
- Uses uvicorn to run the application

### Docker Compose

The `docker-compose.yml` file orchestrates the container and defines how it interacts with the host system:

```yaml
version: '3.8'

services:
  auth_service:
    build: .
    container_name: fastapi_auth_service
    ports:
      - "8400:8000"
    volumes:
      # Use descriptive filenames for databases in the root directory
      - ./auth_service_main.db:/app/sql_app.db
      - ./auth_service_logs.db:/app/logs/logs.db
    env_file:
      - .env
    environment:
      - SECRET_KEY=${SECRET_KEY:-}
      - ALGORITHM=${ALGORITHM:-}
      - ACCESS_TOKEN_EXPIRE_MINUTES=${ACCESS_TOKEN_EXPIRE_MINUTES:-}
      # ... other environment variables ...
    restart: unless-stopped
```

Key aspects of the Docker Compose configuration:
- Maps container port 8000 to host port 8400
- Uses descriptive database filenames for better identification
- Loads environment variables from .env file with runtime overrides
- Implements restart policy for reliability

## Environment Variables

### Priority Order

Environment variables for the application are resolved in the following order (highest to lowest priority):

1. **Runtime Environment Variables**: Variables set when starting the container or passed to docker-compose
2. **Values from .env File**: Variables defined in the project's .env file
3. **Application Defaults**: Any defaults defined in the application code

### Available Configuration Options

The authentication service can be configured with the following environment variables:

#### Database Configuration
- **DATABASE_URL**: Connection string for SQLite database (default: `sqlite:///sql_app.db`)

#### Security Settings
- **SECRET_KEY**: Secret key for JWT token signing
- **ALGORITHM**: Encryption algorithm for JWT tokens (default: HS256)
- **ACCESS_TOKEN_EXPIRE_MINUTES**: Token validity period in minutes (default: 30)
- **IDDLE_MINUTES**: User session idle timeout in minutes (default: 30)
- **SERVICE_TOKEN**: Token for inter-service authentication

#### Rate Limiting Configuration
- **RATE_LIMITS_PUBLIC_ROUTES**: Number of allowed requests for public routes (default: 100)
- **RATE_LIMITS_PRIVATE_ROUTES**: Number of allowed requests for authenticated routes (default: 300)
- **RATE_LIMITS_PUBLIC_TIME_UNIT**: Time unit for public rate limiting (default: 10minute)
- **RATE_LIMITS_PRIVATE_TIME_UNIT**: Time unit for private rate limiting (default: 60minute)

#### Logging Configuration
- **LOG_LEVEL**: Logging verbosity level (default: INFO)

## Data Persistence

### Database Files

The application uses two SQLite database files with descriptive names for better identification:

1. **auth_service_main.db**: Main application database for user data (maps to `/app/sql_app.db` in the container)
2. **auth_service_logs.db**: Database for application logs (maps to `/app/logs/logs.db` in the container)

These files are stored in the project root directory on the host system at:
```
/home/vasile/projects/fastapi_auth_service/auth_service_main.db
/home/vasile/projects/fastapi_auth_service/auth_service_logs.db
```

### Volume Mapping

The docker-compose.yml file includes specific volume mappings to ensure data persistence:

```yaml
volumes:
  - ./auth_service_main.db:/app/sql_app.db
  - ./auth_service_logs.db:/app/logs/logs.db
```

These mappings ensure that:
- Database files are stored on the host with descriptive names
- Changes to the databases persist even when containers are restarted or rebuilt
- If database files don't exist, they will be created on the host

## Running the Containerized Application

### Basic Deployment

To start the containerized authentication service:

```bash
cd /path/to/fastapi_auth_service
docker-compose up -d
```

The application will then be accessible at http://localhost:8400.

### Runtime Configuration

You can override environment variables at runtime:

```bash
SECRET_KEY=my_custom_key ACCESS_TOKEN_EXPIRE_MINUTES=60 docker-compose up -d
```

This allows custom configuration without modifying the .env file.

### Container Management

Common commands for managing the containerized application:

```bash
# View container logs
docker-compose logs -f auth_service

# Stop the service
docker-compose down

# Rebuild the container (after code changes)
docker-compose up -d --build

# View container status
docker-compose ps
```

## Security Considerations

- The container runs with a non-root user for security
- Sensitive values (SECRET_KEY, SERVICE_TOKEN) should be set securely and not committed to source control
- Consider using Docker Secrets for production environments
- The .env file should be in .gitignore to avoid exposing sensitive information
- The main application code is not mounted as a volume in production for security

## Troubleshooting

**Database Errors**:
- Ensure database file permissions allow the container user to read/write
- Check that the volume mappings in docker-compose.yml are correct
- Look for the database files in the project root with the names `auth_service_main.db` and `auth_service_logs.db`

**Environment Variable Issues**:
- Verify that your .env file contains all required variables
- Check that values are properly formatted (no extra spaces, quotes, etc.)
- Use `docker-compose config` to see the resolved configuration

**Container Won't Start**:
- Check container logs with `docker-compose logs auth_service`
- Verify port 8400 is not already in use on the host
- Ensure the Dockerfile and docker-compose.yml are in the project root

## Database Backup

To backup your database files, you can simply copy the database files from your project root:

```bash
# Create a timestamped backup
cp auth_service_main.db auth_service_main.db.backup-$(date +%Y%m%d)
cp auth_service_logs.db auth_service_logs.db.backup-$(date +%Y%m%d)

# Or compress them
tar -czf auth_service_db_backup-$(date +%Y%m%d).tar.gz auth_service_main.db auth_service_logs.db
```