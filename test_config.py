import os
from app.utils.config import settings, ENV_FILE

print("Environment file path:", ENV_FILE)
print("Environment file exists:", os.path.exists(ENV_FILE))
print("Database URL from settings:", settings.DATABASE_URL)
print("DATABASE_URL environment variable:", os.environ.get('DATABASE_URL'))

# Try to force reload the .env file
from dotenv import load_dotenv
print("\nReloading .env file...")
load_dotenv(dotenv_path=ENV_FILE, override=True)
print("DATABASE_URL after explicit reload:", os.environ.get('DATABASE_URL'))

# Try to get settings directly from BaseSettings
from app.utils.config import Settings
new_settings = Settings()
print("\nDatabase URL from fresh settings instance:", new_settings.DATABASE_URL)
