"""Configuration loaded from environment variables."""
from pydantic import field_validator
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Postgres
    db_host: str = "postgres"
    db_port: int = 5432
    db_name: str = "launchpad"
    db_user: str = "launchpad_api_user"
    # No required-value default. Compose cannot make a required-variable guard
    # conditional (it interpolates every service regardless of profiles), so
    # DB_PASSWORD arrives as an empty string when the feature is off. Validating
    # at import instead would make the module unimportable without a database
    # password, which blocks any test job that does not need one.
    db_password: str = ""

    # SMTP
    smtp_host: str = "mailpit"
    smtp_port: int = 1025
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = False
    from_address: str = "noreply@askii.ai"
    from_name: str = "FOSS Launchpad"

    # Valkey/Redis, backing store for the rate limiter (src/rate_limit.py).
    # Database 11: 2, 5, 6, 7, 8, 9, 10, 12, 13 and 14 are claimed by other
    # services in docker-compose.yml; 11 is free.
    redis_url: str = "redis://valkey:6379/11"

    # Resend is 3/day rather than a rounder number because after the
    # squatting fix it is one of only two things bounding how often an
    # address the caller does not own can be mailed. The other is that
    # /api/email charges a repeat submission of the address the caller
    # already holds to this same resend bucket, rather than to the far
    # larger submit allowance. Raising either raises the harassment
    # budget, so treat both as load-bearing rather than hygiene.
    #
    # The residual: routing only catches *consecutive* submissions of the
    # same address. Alternating between two addresses burns both buckets
    # rather than staying on the larger one -- measured at 4 sends in 6
    # attempts -- so per-account outbound stays capped, but per-victim it
    # is looser than the same-address case. Accepted: the caller is
    # authenticated and the total is bounded. Tightening it would mean
    # per-(account, address) counters.
    rate_limit_submit_per_hour: int = 3
    rate_limit_submit_per_day: int = 10
    rate_limit_resend_per_minute: int = 1
    rate_limit_resend_per_day: int = 3
    # Platform-wide daily ceiling: bounds damage from a compromised account and
    # protects the shared SMTP quota that Plane invites and Outline
    # notifications also draw on.
    rate_limit_global_per_day: int = 500

    # Launchpad-specific
    platform_protocol: str = "https"
    platform_domain: str = "foss.local.dev"
    verification_link_expiry_hours: int = 24

    # Verify-gate (ADR-0018)
    # Compared verbatim against the address mpass-auth-proxy builds, so it must
    # be the same string. mpass .strip()s its copy; mirror that below or a
    # trailing space in DEFAULT_EMAIL_DOMAIN silently breaks REFRESH detection.
    synthetic_email_domain: str = ""
    gate_cache_ttl_seconds: int = 10

    @field_validator("synthetic_email_domain", mode="before")
    @classmethod
    def _strip_synthetic_domain(cls, v):
        """Mirror mpass-auth-proxy, which .strip()s its copy of this value.

        The gate compares the email claim verbatim against f"{sid}@{domain}", so
        a trailing space here and not there means REFRESH never matches and a
        verified user is waved through still carrying the synthetic address."""
        return v.strip() if isinstance(v, str) else v

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

