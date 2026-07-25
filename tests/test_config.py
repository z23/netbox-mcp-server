"""Tests for configuration management."""

import logging
import sys
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from netbox_mcp_server.config import Settings, configure_logging
from netbox_mcp_server.server import parse_cli_args


def test_settings_requires_netbox_url():
    """Test that Settings requires NETBOX_URL."""
    # Isolate from .env file by patching model_config
    with (
        patch.dict("os.environ", {}, clear=True),
        pytest.raises(ValidationError, match="netbox_url"),
    ):
        Settings(netbox_token="test-token", _env_file=None)


def test_settings_requires_netbox_token():
    """Test that Settings requires NETBOX_TOKEN."""
    # Isolate from .env file by patching model_config
    with (
        patch.dict("os.environ", {}, clear=True),
        pytest.raises(ValidationError, match="netbox_token"),
    ):
        Settings(netbox_url="https://netbox.example.com/", _env_file=None)


def test_settings_validates_url_format():
    """Test that invalid URLs are rejected."""

    with pytest.raises(ValidationError, match="Input should be a valid URL"):
        Settings(netbox_url="not-a-valid-url", netbox_token="test-token")


def test_settings_validates_port_range():
    """Test that port must be in valid range."""

    with pytest.raises(ValidationError, match="port"):
        Settings(
            netbox_url="https://netbox.example.com/",
            netbox_token="test-token",
            port=99999,
        )


def test_settings_masks_secrets_in_summary():
    """Test that get_effective_config_summary masks secrets."""

    settings = Settings(netbox_url="https://netbox.example.com/", netbox_token="super-secret-token")

    summary = settings.get_effective_config_summary()

    assert summary["netbox_token"] == "***REDACTED***"
    assert "super-secret-token" not in str(summary)


# ===== MCP Auth Token Tests =====


def test_auth_token_read_from_env():
    """MCP_AUTH_TOKEN env var populates the secret field."""
    with patch.dict(
        "os.environ",
        {
            "NETBOX_URL": "https://netbox.example.com/",
            "NETBOX_TOKEN": "tok",
            "MCP_AUTH_TOKEN": "bearer-secret",
        },
        clear=True,
    ):
        settings = Settings(_env_file=None)

    assert settings.mcp_auth_token is not None
    assert settings.mcp_auth_token.get_secret_value() == "bearer-secret"


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_auth_token_normalized_to_none(blank):
    """Empty or whitespace-only tokens are treated as unset (guards fail-open)."""
    settings = Settings(
        netbox_url="https://netbox.example.com/",
        netbox_token="tok",
        mcp_auth_token=blank,
        _env_file=None,
    )

    assert settings.mcp_auth_token is None


def test_auth_token_masked_in_summary():
    """A configured auth token is redacted in the HTTP config summary."""
    settings = Settings(
        netbox_url="https://netbox.example.com/",
        netbox_token="tok",
        transport="http",
        mcp_auth_token="bearer-secret",
        _env_file=None,
    )

    summary = settings.get_effective_config_summary()

    assert summary["mcp_auth_token"] == "***REDACTED***"
    assert "bearer-secret" not in str(summary)


# ===== CLI Argument Parsing Tests =====


def test_parse_cli_args_multiple():
    """Test that multiple arguments are captured."""

    original_argv = sys.argv
    try:
        sys.argv = [
            "server.py",
            "--netbox-url",
            "https://test.example.com/",
            "--transport",
            "http",
            "--port",
            "9000",
            "--log-level",
            "DEBUG",
            "--no-verify-ssl",
        ]
        result = parse_cli_args()
        assert result["netbox_url"] == "https://test.example.com/"
        assert result["transport"] == "http"
        assert result["port"] == 9000
        assert result["log_level"] == "DEBUG"
        assert result["verify_ssl"] is False
    finally:
        sys.argv = original_argv


def test_parse_cli_args_mcp_auth_token():
    """--mcp-auth-token maps to the mcp_auth_token overlay key (typo guard)."""

    original_argv = sys.argv
    try:
        sys.argv = ["server.py", "--mcp-auth-token", "bearer-secret"]
        result = parse_cli_args()
        assert result["mcp_auth_token"] == "bearer-secret"
    finally:
        sys.argv = original_argv


# ===== Logging Configuration Tests =====


def test_configure_logging_suppresses_http_clients():
    """Test that HTTP client loggers are suppressed at INFO level."""

    configure_logging("INFO")

    urllib3_logger = logging.getLogger("urllib3")
    httpx_logger = logging.getLogger("httpx")

    assert urllib3_logger.level == logging.WARNING
    assert httpx_logger.level == logging.WARNING


def test_configure_logging_shows_http_clients_at_debug():
    """Test that HTTP client loggers are shown at DEBUG level."""
    configure_logging("DEBUG")

    root_logger = logging.getLogger()
    urllib3_logger = logging.getLogger("urllib3")
    httpx_logger = logging.getLogger("httpx")

    assert root_logger.level == logging.DEBUG
    assert urllib3_logger.level == logging.DEBUG
    assert httpx_logger.level == logging.DEBUG


# ===== Timeout & Write-Safety Settings =====


def _settings(**kw):
    base = {
        "netbox_url": "https://netbox.example.com/",
        "netbox_token": "tok",
        "_env_file": None,
    }
    base.update(kw)
    return Settings(**base)


def test_netbox_timeout_defaults_to_30():
    assert _settings().netbox_timeout == 30.0


def test_netbox_timeout_rejects_non_positive():
    with pytest.raises(ValidationError, match="netbox_timeout"):
        _settings(netbox_timeout=0)


def test_write_denied_types_default_covers_sensitive_types():
    denied = _settings().write_denied_types
    # Credentials and permissions.
    assert "users.*" in denied
    # Code execution and outbound callbacks.
    assert "extras.webhook" in denied
    assert "extras.eventrule" in denied
    assert "extras.script" in denied
    # Server-rendered Jinja2 templates.
    assert "extras.configtemplate" in denied
    assert "extras.exporttemplate" in denied
    # The path by which scripts and templates are ingested.
    assert "core.datasource" in denied
    # Deleting one destroys that field's data across every object of its type.
    assert "extras.customfield" in denied


def test_allow_unauthenticated_writes_defaults_false():
    assert _settings().allow_unauthenticated_writes is False


def test_cors_origins_accepts_bare_string():
    """A single origin string is wrapped into a list (env footgun)."""
    settings = _settings(cors_origins="http://localhost:6274")
    assert settings.cors_origins == ["http://localhost:6274"]


def test_cors_origins_accepts_json_list_string():
    settings = _settings(cors_origins='["http://localhost:6274", "https://app.example.com"]')
    assert settings.cors_origins == ["http://localhost:6274", "https://app.example.com"]


def test_cors_origins_rejects_invalid_url():
    with pytest.raises(ValidationError, match="Invalid CORS_ORIGIN"):
        _settings(cors_origins=["not-a-url"])


# ===== Startup Safety Guard (_unsafe_runtime_config) =====


def test_unsafe_when_http_writes_without_auth():
    """Writes on HTTP with no auth token must be flagged as unsafe to start."""
    from netbox_mcp_server.server import _unsafe_runtime_config

    settings = _settings(transport="http", enable_writes=True)
    assert _unsafe_runtime_config(settings) is not None


def test_safe_when_auth_token_set():
    from netbox_mcp_server.server import _unsafe_runtime_config

    settings = _settings(transport="http", enable_writes=True, mcp_auth_token="secret")
    assert _unsafe_runtime_config(settings) is None


def test_safe_when_unauthenticated_writes_explicitly_allowed():
    from netbox_mcp_server.server import _unsafe_runtime_config

    settings = _settings(transport="http", enable_writes=True, allow_unauthenticated_writes=True)
    assert _unsafe_runtime_config(settings) is None


def test_safe_for_stdio_writes_without_auth():
    """stdio transport is not network-exposed, so writes without a token are fine."""
    from netbox_mcp_server.server import _unsafe_runtime_config

    settings = _settings(transport="stdio", enable_writes=True)
    assert _unsafe_runtime_config(settings) is None


def test_unsafe_when_wildcard_cors_without_auth():
    """Wildcard CORS with no token lets any visited web page read NetBox data."""
    from netbox_mcp_server.server import _unsafe_runtime_config

    settings = _settings(transport="http", cors_origins=["*"])
    reason = _unsafe_runtime_config(settings)
    assert reason is not None
    assert "CORS_ORIGINS" in reason


def test_wildcard_cors_safe_when_auth_token_set():
    """A bearer token is what actually closes the cross-origin read path."""
    from netbox_mcp_server.server import _unsafe_runtime_config

    settings = _settings(transport="http", cors_origins=["*"], mcp_auth_token="secret")
    assert _unsafe_runtime_config(settings) is None


def test_specific_cors_origins_without_auth_still_start():
    """Naming explicit origins is not the same affirmative act as '*'."""
    from netbox_mcp_server.server import _unsafe_runtime_config

    settings = _settings(transport="http", cors_origins=["http://localhost:6274"])
    assert _unsafe_runtime_config(settings) is None


def test_wildcard_cors_safe_for_stdio():
    """CORS is meaningless without the HTTP transport."""
    from netbox_mcp_server.server import _unsafe_runtime_config

    settings = _settings(transport="stdio", cors_origins=["*"])
    assert _unsafe_runtime_config(settings) is None


def test_wildcard_cors_not_excused_by_allow_unauthenticated_writes():
    """ALLOW_UNAUTHENTICATED_WRITES covers the write endpoint, not wildcard CORS."""
    from netbox_mcp_server.server import _unsafe_runtime_config

    settings = _settings(
        transport="http",
        enable_writes=True,
        allow_unauthenticated_writes=True,
        cors_origins=["*"],
    )
    reason = _unsafe_runtime_config(settings)
    assert reason is not None
    assert "CORS_ORIGINS" in reason
