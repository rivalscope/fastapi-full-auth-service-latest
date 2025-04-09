"""
# Logging Module
---

## Purpose
This module provides a comprehensive logging system for the application that outputs logs to
both the console and a SQLite database for persistent storage and future analysis.

## Functionality
- Creates and manages a SQLite database for structured log storage
- Configures loggers with appropriate handlers and formatting
- Provides utility functions to retrieve loggers and mask sensitive data
- Captures source IP addresses for request logging

## Flow
1. Creates a logs directory if it doesn't exist
2. Sets up a root logger with console and SQLite handlers when setup_logging() is called
3. Log messages are simultaneously displayed on console and stored in database
4. IP addresses can be included in log entries for request tracking

## Security
- Provides utilities to mask sensitive information like passwords
- Stores logs securely in a local SQLite database
- Implements proper error handling to prevent logging system failures
- Captures source IP for security auditing and threat detection

## Dependencies
- Python standard libraries: os, logging, sys, datetime, sqlite3
- Application configuration from settings module

## Usage
```python
# Initialize logging
from app.utils.logging import setup_logging, get_logger, mask_password
setup_logging()

# Get a logger for a specific component
logger = get_logger("component_name")

# Log messages with IP address
extra = {'ip_address': request.client.host}
logger.info("User login attempt", extra=extra)

# Regular log messages
logger.info("Operation successful")
logger.error(f"Login attempt failed for user: {username}, password: {mask_password(password)}")
```
"""

import os
import logging
import sys
from datetime import datetime
import sqlite3

from app.utils.config import settings

# Create logs directory if it doesn't exist
os.makedirs('logs', exist_ok=True)

class SQLiteHandler(logging.Handler):
    """Custom logging handler that stores log entries in a SQLite database."""
    
    def __init__(self, db_path):
        # Initialize the handler and set up the database
        logging.Handler.__init__(self)
        self.db_path = db_path
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create logs table if it doesn't exist with ip_address column
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                logger TEXT,
                level TEXT,
                message TEXT,
                ip_address TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def emit(self, record):
        # Process a log record and store it in the database
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Format timestamp for readability
            timestamp = datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')
            
            # Extract IP address if available in the log record
            ip_address = getattr(record, 'ip_address', None)
            
            # Insert log entry into the database with IP address
            cursor.execute(
                "INSERT INTO logs (timestamp, logger, level, message, ip_address) VALUES (?, ?, ?, ?, ?)",
                (timestamp, record.name, record.levelname, record.getMessage(), ip_address)
            )
            
            conn.commit()
            conn.close()
        except Exception:
            self.handleError(record)

class IPAdapter(logging.LoggerAdapter):
    """Logger adapter that includes IP address information in log records."""
    
    def process(self, msg, kwargs):
        # Ensure 'extra' dict exists in kwargs
        if 'extra' not in kwargs:
            kwargs['extra'] = {}
        
        # If we have an ip_address in our context but not in kwargs, add it
        if hasattr(self, 'ip_address') and 'ip_address' not in kwargs['extra']:
            kwargs['extra']['ip_address'] = self.ip_address
            
        return msg, kwargs

def get_logger(name, ip_address=None):
    # Return a named logger instance for a specific component, optionally with IP tracking
    logger = logging.getLogger(name)
    
    if ip_address:
        # Create an adapter that will include the IP address in all logs
        adapter = IPAdapter(logger)
        adapter.ip_address = ip_address
        return adapter
    
    return logger

def setup_logging():
    # Configure the root logger with appropriate handlers and formatting
    logger = logging.getLogger()
    
    # Set log level from configuration
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    logger.setLevel(log_level)
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Create a formatter for consistent log formatting
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Add console output handler
    console_handler = logging.StreamHandler(stream=sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Add database storage handler
    db_handler = SQLiteHandler('logs/logs.db')
    logger.addHandler(db_handler)
    
    # Log initialization status
    logger.info(f"Logging initialized at level {settings.LOG_LEVEL}")
    
    # Prevent duplicate logs from uvicorn's access logs
    logging.getLogger("uvicorn.access").propagate = False
    
    return logger

def mask_password(password):
    # Mask sensitive information to prevent security leaks in logs
    return "xxxxxxxxxx" if password else None

def log_with_ip(logger, level, message, ip_address, *args, **kwargs):
    """Helper function to log messages with source IP address."""
    if 'extra' not in kwargs:
        kwargs['extra'] = {}
    
    kwargs['extra']['ip_address'] = ip_address
    
    if level.upper() == 'DEBUG':
        logger.debug(message, *args, **kwargs)
    elif level.upper() == 'INFO':
        logger.info(message, *args, **kwargs)
    elif level.upper() == 'WARNING':
        logger.warning(message, *args, **kwargs)
    elif level.upper() == 'ERROR':
        logger.error(message, *args, **kwargs)
    elif level.upper() == 'CRITICAL':
        logger.critical(message, *args, **kwargs)
    else:
        logger.info(message, *args, **kwargs)
