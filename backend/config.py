from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

_ENV_FILE = Path(__file__).parent / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(_ENV_FILE), env_file_encoding="utf-8")

    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    ipinfo_token: str = ""
    shodan_api_key: str = ""

    max_file_size_mb: int = 50


settings = Settings()
