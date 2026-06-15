"""Configuration loaded from environment variables."""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Postgres
    db_host: str = "postgres"
    db_port: int = 5432
    db_name: str = "launchpad"
    db_user: str = "launchpad_api_user"
    db_password: str

    # SMTP
    smtp_host: str = "mailpit"
    smtp_port: int = 1025
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = False
    from_address: str = "noreply@askii.ai"
    from_name: str = "FOSS Launchpad"

    # Launchpad-specific
    platform_protocol: str = "https"
    platform_domain: str = "foss.local.dev"
    verification_link_expiry_hours: int = 24

    class Config:
        env_file = ".env"
        env_prefix = ""

    @property
    def db_dsn(self) -> str:
        return f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    @property
    def verification_url_base(self) -> str:
        return f"{self.platform_protocol}://{self.platform_domain}/api/verify"


settings = Settings()
