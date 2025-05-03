"""
Purpose:
    This file serves as the central initialization point for all API routers in the application. 
    It imports and organizes routers from various modules to ensure modularity and maintainability.

Functionality:
    - Imports routers from different modules.
    - Assigns aliases to routers for better readability and usage.

Flow:
    - Each router is imported from its respective module.
    - These routers are then used in the main application to define API endpoints.

Security:
    - Ensures modular separation of concerns, allowing for easier implementation of security measures in individual modules.
    - Sensitive operations like authentication and token validation are handled in their respective routers.

Dependencies:
    - Relies on the presence of router objects in the respective modules under `app.routers`.

Usage:
    - This file is imported in the main application to include all the defined routers.
    - Example: `from app.routers import *`

Endpoints:
    - No endpoints are defined in this file directly. Endpoints are defined in the respective router modules.
"""

# Importing the router for account recovery operations
from app.routers.accounts_recovery import recovery_router

# Importing the router for admin account management operations
from app.routers.admin_accounts_management import admin_router

# Importing the router for inter-service token validation operations
from app.routers.inter_service_token_validation import inter_service_router

# Importing the router for user account management operations
from app.routers.user_account_management import accounts_router

# Importing the router for user authentication operations
from app.routers.users_auth import auth_router

# Importing the router for user registration operations
from app.routers.users_registration import registration_router