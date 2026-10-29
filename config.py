"""Configuration loading and validation for the honeypot.

All configuration comes from environment variables so that the same package
runs locally (Windows) and on Render without code changes.  Secrets are never
hardcoded; see ``.env.example`` for the local-development template.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


class ConfigError(ValueError):
    """Raised when an environment variable has an unusable value."""


def _env_int(name: str, default: int) -> int:
    """Read an integer environment variable, validating it clearly."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw.strip())
    except ValueError:
        raise ConfigError(
            f"Environment variable {name} must be an integer, got {raw!r}"
        ) from None


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Config:
    """Runtime configuration, populated from environment variables."""

    # PostgreSQL URL (production). Empty string means "use local SQLite".
    database_url: str = ""

    # Directory for the local SQLite database file (and exports).
    data_dir: str = "."

    # Number of reverse proxies between the Internet and this app.
    # 0 (default) means forwarded-client headers are NOT trusted and
    # request.remote_addr (the socket peer) is recorded as the source IP.
    # For Render with one reverse proxy hop the correct value to VERIFY is 1.
    # Never guess this value: verify in the deployment logs/docs first.
    proxy_trusted_hops: int = 0

    # Mark requests that arrive over loopback (local development /
    # functional tests) as synthetic so they can be excluded from
    # real-Internet statistics.
    mark_local_synthetic: bool = True

    # Optional GeoLite2 city/country database path.  When absent, country
    # values are simply left unknown.  Never guess a country.
    geoip_db_path: str = ""

    # Version stamped into every telemetry record for reproducibility.
    collector_version: str = field(default="1.0.0", init=False)

    app_debug: bool = False

    extra: dict = field(default_factory=dict)


def get_config() -> Config:
    """Build the runtime configuration from environment variables."""
    config = Config(
        database_url=os.environ.get("DATABASE_URL", "").strip(),
        data_dir=os.environ.get("DATA_DIR", ".").strip() or ".",
        proxy_trusted_hops=_env_int("PROXY_TRUSTED_HOPS", 0),
        mark_local_synthetic=_env_bool("MARK_LOCAL_SYNTHETIC", True),
        geoip_db_path=os.environ.get("GEOIP_DB_PATH", "").strip(),
        app_debug=_env_bool("APP_DEBUG", False),
    )

    if config.proxy_trusted_hops < 0:
        raise ConfigError("PROXY_TRUSTED_HOPS must be 0 or a positive integer")

    if config.database_url.startswith(("postgres://", "postgresql://")):
        pass  # PostgreSQL handled by the telemetry store
    elif config.database_url:
        raise ConfigError(
            "DATABASE_URL must be a PostgreSQL URL "
            "(postgres://...) or left unset to use SQLite"
        )

    return config
