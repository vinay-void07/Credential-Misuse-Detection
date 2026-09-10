import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")

class Settings:
    PROJECT_NAME: str = os.getenv("PROJECT_NAME", "Prism Network")
    VERSION: str = os.getenv("VERSION", "1.0.0")
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    DEBUG: bool = os.getenv("DEBUG", "True").lower() in ("true", "1", "t")

    # Security & JWT
    JWT_SECRET: str = os.getenv("JWT_SECRET", "prism-super-secret-key-change-in-production-min32chars")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/data/prism.db".replace("\\", "/"))

    # Working Hours (24-hour clock)
    WORK_HOUR_START: int = int(os.getenv("WORK_HOUR_START", "9"))
    WORK_HOUR_END: int = int(os.getenv("WORK_HOUR_END", "18"))

    # Risk Engine & Alert Thresholds (0-100 scale)
    ALERT_THRESHOLD: float = float(os.getenv("ALERT_THRESHOLD", "45.0"))
    CRITICAL_THRESHOLD: float = float(os.getenv("CRITICAL_THRESHOLD", "80.0"))
    BULK_DOWNLOAD_THRESHOLD: int = int(os.getenv("BULK_DOWNLOAD_THRESHOLD", "10"))
    REQUEST_RATE_THRESHOLD: float = float(os.getenv("REQUEST_RATE_THRESHOLD", "15.0"))

    # Component weights
    ML_WEIGHT: float = float(os.getenv("ML_WEIGHT", "40.0"))
    RULE_WEIGHT: float = float(os.getenv("RULE_WEIGHT", "60.0"))

    # Model file path
    MODEL_PATH: str = str(BASE_DIR / "models" / "isolation_forest.joblib")

settings = Settings()
