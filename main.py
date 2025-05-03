import os
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager

from app.utils.db import create_db_and_tables
from app.utils.config import settings
from app.routers import auth_router, accounts_router, admin_router, recovery_router, registration_router, inter_service_router
from app.utils.logging import setup_logging, get_logger

# Setup logging
setup_logging()
logger = get_logger(__name__)

# Format the rate limit string from environment variables
public_rate_limit = f"{settings.RATE_LIMITS_PUBLIC_ROUTES}/{settings.RATE_LIMITS_PUBLIC_TIME_UNIT}"
private_rate_limit = f"{settings.RATE_LIMITS_PRIVATE_ROUTES}/{settings.RATE_LIMITS_PRIVATE_TIME_UNIT}"

# Initialize rate limiter with configured values
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[public_rate_limit]  # Default to public rate limit
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown events
    Replaces the deprecated on_event handlers
    """
    # Startup code
    logger.info("Application starting up")
    logger.info(f"Rate limits configured: Public: {public_rate_limit}, Private: {private_rate_limit}")
    create_db_and_tables()
    logger.info("Database and tables initialized")
    
    yield
    
    # Shutdown code
    logger.info("Application shutting down")

# Initialize FastAPI app with lifespan
app = FastAPI(
    title="FastAPI Auth System",
    description="A simple, clean FastAPI login system with SQLite, SQLAlchemy, and Pydantic",
    version="1.0.0",
    lifespan=lifespan
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)
app.include_router(registration_router)
app.include_router(recovery_router)
app.include_router(accounts_router)
app.include_router(admin_router)
app.include_router(inter_service_router)

# Custom OpenAPI schema with security configurations
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    
    # Add security schemes
    openapi_schema["components"] = openapi_schema.get("components", {})
    openapi_schema["components"]["securitySchemes"] = {
        "userAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "OPAQUE"  # short-lived user key
        },
        "serviceAuth": {
            "type": "apiKey",
            "in": "header",
            "name": "X-Service-Token"  # only inter-service hops add this
        }
    }
    
    # Apply userAuth globally to all endpoints
    openapi_schema["security"] = [{"userAuth": []}]
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

@app.get("/", tags=["Root"], openapi_extra={"security": []})
async def root():
    """Root endpoint, returns a welcome message"""
    logger.info("Root endpoint accessed")
    return {"message": "Welcome to the FastAPI Auth System"}

if __name__ == "__main__":
    # Run the application with uvicorn
    logger.info("Starting application server")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
