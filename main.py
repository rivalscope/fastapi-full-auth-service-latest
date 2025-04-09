import os
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from contextlib import asynccontextmanager

from app.utils.db import create_db_and_tables
from app.routers import auth_router, accounts_router, admin_router, recovery_router, registration_router, inter_service_router
from app.utils.logging import setup_logging, get_logger

# Setup logging
setup_logging()
logger = get_logger(__name__)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager for startup and shutdown events
    Replaces the deprecated on_event handlers
    """
    # Startup code
    logger.info("Application starting up")
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

@app.get("/", tags=["Root"])
async def root():
    """Root endpoint, returns a welcome message"""
    logger.info("Root endpoint accessed")
    return {"message": "Welcome to the FastAPI Auth System"}

if __name__ == "__main__":
    # Run the application with uvicorn
    logger.info("Starting application server")
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
