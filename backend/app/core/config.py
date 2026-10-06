from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "CYBERSENTINEL AI"
    environment: str = "development"
    database_url: str = "postgresql+asyncpg://postgres:postgres@postgres:5432/cybersentinel"
    redis_url: str = "redis://redis:6379/0"
    jwt_secret: str
    jwt_access_minutes: int = 15
    jwt_refresh_days: int = 30
    encryption_key: str
    cors_origins: str = "http://localhost:3000"
    default_target: str = "mriranfa.site"
    registration_enabled: bool = True
    max_body_bytes: int = 2_000_000
    scan_timeout_seconds: int = 12
    max_redirects: int = 5
    max_concurrency_per_scan: int = 5
    per_target_delay_seconds: float = 0.6
    cloudflare_api_token: str | None = None
    cloudflare_account_id: str | None = None
    cloudflare_zone_id: str | None = None
    cloudflare_ai_model: str = "@cf/meta/llama-3.1-8b-instruct"
    cloudflare_ai_token: str | None = None
    cloudflare_api_base: str = "https://api.cloudflare.com/client/v4"
    log_level: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

@lru_cache
def get_settings() -> Settings:
    return Settings()
