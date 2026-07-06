"""Global configuration for the DAST scanner backend."""

import os

class Settings:
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEFAULT_MAX_DEPTH: int = 2
    DEFAULT_MAX_CONCURRENCY: int = 5
    DEFAULT_PAGE_TIMEOUT_MS: int = 5000
    USER_AGENT: str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    SSE_PING_INTERVAL: int = 15  # seconds
    MAX_BODY_SIZE: int = 2 * 1024 * 1024  # 2 MB - lower size for speed
    REQUEST_DELAY: float = 0.5  # Add a 500ms delay by default to be nice
    
    # Celery & Redis config
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    CELERY_BROKER_URL: str = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/1")
    CELERY_RESULT_BACKEND: str = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/2")
    
    # API Key for CI/CD Integration
    SENTINEL_API_KEY: str = os.getenv("SENTINEL_API_KEY", "ci-cd-secret-key-change-me-in-prod")


settings = Settings()
