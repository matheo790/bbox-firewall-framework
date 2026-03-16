import os

from dotenv import load_dotenv

load_dotenv()


def env_bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


class Config:
    API_HOST = os.getenv("API_HOST", "0.0.0.0")
    API_PORT = int(os.getenv("API_PORT", "5000"))
    DEBUG = env_bool("DEBUG", "false")

    APP_USERNAME = os.getenv("APP_USERNAME", "admin")
    APP_PASSWORD = os.getenv("APP_PASSWORD", "change-me")
    JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-change-me")
    JWT_EXP_MINUTES = int(os.getenv("JWT_EXP_MINUTES", "5"))

    BBOX_HOST = os.getenv("BBOX_HOST", "https://mabbox.bytel.fr")
    BBOX_PASSWORD = os.getenv("BBOX_PASSWORD", "")
    BBOX_VERIFY_SSL = env_bool("BBOX_VERIFY_SSL", "false")
