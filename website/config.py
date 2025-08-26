import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-in-prod")
    DEBUG = os.getenv("DEBUG", "True") == "True"
    
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", "sqlite:///instance/site.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "website", "static", "Uploads"
    )
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB

    STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
    STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY")
    STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
    STRIPE_API_VERSION = "2025-07-30.basil"

    PRICE_ID_BASIC = os.getenv("PRICE_ID_BASIC")
    PRICE_ID_ADVANCED = os.getenv("PRICE_ID_ADVANCED")
    PRICE_ID_PREMIUM = os.getenv("PRICE_ID_PREMIUM")
