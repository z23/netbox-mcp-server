"""Configuration management for NetBox MCP Server."""

import json
import logging
import logging.config
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import AnyUrl, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Object types the write tools refuse to mutate by default when ENABLE_WRITES=true.
# These are security-critical: writing them can mint credentials, grant permissions,
# run code, or destroy data well beyond the named object. An entry ending in ".*"
# matches a whole app label (e.g. "users.*"). This is defense-in-depth on top of
# NetBox API-token scoping, and is overridable via the write_denied_types setting
# (WRITE_DENIED_TYPES).
DEFAULT_WRITE_DENIED_TYPES: list[str] = [
    # Credentials and permissions.
    "users.*",
    # Code execution and outbound callbacks.
    "extras.webhook",
    "extras.eventrule",
    "extras.script",
    # Server-rendered Jinja2 templates — another code-execution path.
    "extras.configtemplate",
    "extras.exporttemplate",
    # Data sources are how scripts and config templates get INTO NetBox. Denying
    # extras.script while leaving the ingestion mechanism writable would be a hole
    # in this deny-list's own threat model.
    "core.datasource",
    # Deleting a custom field destroys that field's data on every object of its
    # type, so the blast radius is far larger than the single object named.
    "extras.customfield",
]


class Settings(BaseSettings):
    """
    Centralized configuration for NetBox MCP Server.

    Configuration precedence: CLI > Environment > .env file > Defaults

    Environment variables should match field names (e.g., NETBOX_URL, TRANSPORT).
    """

    # ===== Core NetBox Settings =====
    netbox_url: AnyUrl
    """Base URL of the NetBox instance (e.g., https://netbox.example.com/)"""

    netbox_token: SecretStr
    """API token for NetBox authentication (treated as secret)"""

    netbox_timeout: float = 30.0
    """Per-request timeout (seconds) for calls to the NetBox API."""

    # ===== Transport Settings =====
    transport: Literal["stdio", "http"] = "stdio"
    """MCP transport protocol to use (stdio for Claude Desktop, http for web clients)"""

    host: str = "127.0.0.1"
    """Host address to bind HTTP server (only used when transport='http')"""

    port: int = 8000
    """Port to bind HTTP server (only used when transport='http')"""

    cors_origins: list[str] = Field(
        default_factory=list,
        description="Browser origins allowed for HTTP CORS. Use * to allow any origin.",
    )

    mcp_auth_token: SecretStr | None = Field(
        default=None,
        description=(
            "Optional bearer token required on the HTTP transport endpoint. "
            "When set, requests to the MCP endpoint must send "
            "'Authorization: Bearer <token>'. Only applied when transport='http'."
        ),
    )
    """Optional bearer token protecting the HTTP transport endpoint (treated as secret)"""

    # ===== Plugin Discovery Settings =====
    enable_plugin_discovery: bool = False
    """Whether to auto-discover plugin object types from NetBox at startup"""

    # ===== Write Tool Settings =====
    enable_writes: bool = False
    """Whether to register create/update/delete tools. Requires NetBox token with write perms."""

    write_denied_types: list[str] = Field(
        default_factory=lambda: list(DEFAULT_WRITE_DENIED_TYPES),
        description=(
            "Object types the write tools refuse to mutate even when ENABLE_WRITES=true. "
            "Entries ending in '.*' match a whole app label. Defense-in-depth on top of "
            "NetBox token scoping. Set to [] to disable (rely on token scoping alone)."
        ),
    )
    """Object types the write tools refuse to mutate (defense-in-depth deny-list)."""

    allow_unauthenticated_writes: bool = False
    """Permit HTTP transport with writes enabled but no MCP_AUTH_TOKEN (trusted localhost only)."""

    # ===== Security Settings =====
    verify_ssl: bool = True
    """Whether to verify SSL certificates when connecting to NetBox"""

    # ===== Observability Settings =====
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    """Logging verbosity level"""

    # ===== Pydantic Configuration =====
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="",  # No prefix, use field names directly
        extra="ignore",  # Ignore unknown environment variables
        case_sensitive=False,  # Environment variables are case-insensitive
    )

    # ===== Validators =====

    @field_validator("port")
    @classmethod
    def validate_port(cls, v: int) -> int:
        """Ensure port is in valid range."""
        if not (0 < v < 65536):
            raise ValueError(f"Port must be between 1 and 65535, got {v}")
        return v

    @field_validator("netbox_timeout")
    @classmethod
    def validate_netbox_timeout(cls, v: float) -> float:
        """Ensure the NetBox request timeout is positive."""
        if v <= 0:
            raise ValueError(f"netbox_timeout must be greater than 0, got {v}")
        return v

    @field_validator("mcp_auth_token", mode="after")
    @classmethod
    def normalize_auth_token(cls, v: SecretStr | None) -> SecretStr | None:
        """Treat an empty or whitespace-only token as unset.

        A present-but-empty value (e.g. an unpopulated container secret
        rendering as MCP_AUTH_TOKEN=) would otherwise build a verifier that
        accepts an empty bearer while the server logs that auth is enabled.
        Normalizing to None here keeps every consumer in agreement.
        """
        if v is not None and not v.get_secret_value().strip():
            return None
        return v

    @field_validator("netbox_url")
    @classmethod
    def validate_netbox_url(cls, v: AnyUrl) -> AnyUrl:
        """Ensure NetBox URL has a scheme and host."""
        if not v.scheme or not v.host:
            raise ValueError(
                "NETBOX_URL must include scheme and host (e.g., https://netbox.example.com/)"
            )
        return v

    @model_validator(mode="after")
    def validate_http_transport_requirements(self) -> "Settings":
        """No additional validation needed for HTTP transport; defaults are appropriate."""
        return self

    @field_validator("cors_origins", mode="before")
    @classmethod
    def validate_cors_origins(cls, v: object) -> list[str]:
        """Ensure each CORS origin is a valid URL.

        Accept a single bare origin string (common env footgun) by wrapping it
        in a one-element list. Without this, iterating a str walks characters
        and yields a confusing 'Invalid CORS_ORIGIN: \\'h\\'' error.
        """
        if v is None:
            return []
        if isinstance(v, str):
            stripped = v.strip()
            if not stripped:
                return []
            # JSON list from env (pydantic-settings usually parses this already)
            if stripped.startswith("["):
                parsed_json = json.loads(stripped)
                if not isinstance(parsed_json, list):
                    raise ValueError("CORS_ORIGINS JSON value must be a list of origin strings")
                v = parsed_json
            else:
                v = [stripped]
        if not isinstance(v, list):
            raise ValueError("CORS_ORIGINS must be a list of origin strings")
        for origin in v:
            if not isinstance(origin, str):
                raise ValueError(f"Invalid CORS_ORIGIN: {origin!r} (expected a string)")
            if origin == "*":
                continue
            parsed = urlparse(origin)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(
                    f"Invalid CORS_ORIGIN: {origin!r} (expected format: http://host:port)"
                )
        return v

    def get_effective_config_summary(self) -> dict:
        """
        Return a non-secret summary of effective configuration for logging.

        Returns:
            Dictionary with configuration values (secrets masked)
        """
        summary: dict[str, Any] = {
            "netbox_url": str(self.netbox_url),
            "netbox_token": "***REDACTED***",
            "netbox_timeout": self.netbox_timeout,
            "transport": self.transport,
            "verify_ssl": self.verify_ssl,
            "enable_plugin_discovery": self.enable_plugin_discovery,
            "enable_writes": self.enable_writes,
            "log_level": self.log_level,
        }
        if self.enable_writes:
            summary["write_denied_types"] = self.write_denied_types
        if self.transport == "http":
            summary.update(
                {
                    "host": self.host,
                    "port": self.port,
                    "cors_origins": self.cors_origins,
                    "mcp_auth_token": "***REDACTED***" if self.mcp_auth_token else None,
                    "allow_unauthenticated_writes": self.allow_unauthenticated_writes,
                }
            )
        return summary


def configure_logging(
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
) -> None:
    """
    Configure structured logging using dictConfig.

    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    config: dict[str, Any] = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "console": {
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "console",
                "stream": "ext://sys.stderr",
            },
        },
        "loggers": {
            # Suppress noisy HTTP client logs unless DEBUG
            "urllib3": {
                "level": "WARNING" if log_level != "DEBUG" else "DEBUG",
            },
            "httpx": {
                "level": "WARNING" if log_level != "DEBUG" else "DEBUG",
            },
        },
        "root": {
            "level": log_level,
            "handlers": ["console"],
        },
    }

    logging.config.dictConfig(config)
