"""
# FastAPI Authentication System

## Purpose
This module provides a factory function for creating and configuring a FastAPI application
for authentication purposes. It centralizes application setup with appropriate security
configurations and middleware to ensure consistent application behavior.

## Functionality
- Creates a configured FastAPI application instance with proper metadata
- Implements rate limiting to prevent API abuse and DoS attacks
- Configures CORS for handling cross-origin requests
- Adjusts settings based on environment (testing vs production)
- Sets up proper error handling for rate limit exceptions

## Flow
1. Application creation starts with create_app function call
2. Rate limiter is configured based on environment
3. FastAPI application is instantiated with metadata
4. Middleware and exception handlers are registered
5. Configured application and limiter are returned for use

## Security
- Rate limiting protects against Denial of Service attacks
- CORS configuration controls cross-origin access (currently permissive)
- Exception handling prevents security information disclosure

## Dependencies
- FastAPI: Web framework for building APIs
- slowapi: Rate limiting implementation for FastAPI
- app.utils.logging: Custom logging configuration

## Usage
```python
from app.app import create_app

# Create the application
app, limiter = create_app()

# Register routes
@app.get("/")
@limiter.limit("5/minute")
def root():
    return {"message": "Welcome to the authentication system"}

# Run the application
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

## Endpoints
This file does not define endpoints directly. It provides the application factory
where routes/endpoints are registered in other modules after app creation.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.utils.logging import get_logger

# Initialize logger for this module
logger = get_logger(__name__)

def create_app(testing=False):
    # Configure rate limiter with different settings for testing vs production
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["1000/second"] if testing else None
    )
    
    # Create FastAPI application with metadata for documentation
    app = FastAPI(
        title="FastAPI Auth System",
        description="A simple, clean FastAPI login system with SQLite, SQLAlchemy, and Pydantic",
        version="1.0.0"
    )
    
    # Register rate limiter with the application
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    
    # Configure CORS to handle cross-origin requests
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # In production, this should be restricted to specific origins
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Return both app and limiter for use in main application
    return app, limiter
