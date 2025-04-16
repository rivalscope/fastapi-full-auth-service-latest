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

## Getting Started

To run this project, follow these steps:

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

The entry point is main.py.
The server uses Uvicorn and auto-reloads on code changes.

