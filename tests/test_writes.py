"""Tests for write tool behavior (create/update/delete)."""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from netbox_mcp_server.config import DEFAULT_WRITE_DENIED_TYPES
from netbox_mcp_server.netbox_types import NETBOX_OBJECT_TYPES
from netbox_mcp_server.server import (
    netbox_create_object,
    netbox_delete_object,
    netbox_update_object,
)

# ============================================================================
# Create
# ============================================================================


@patch("netbox_mcp_server.server.netbox")
def test_create_object_happy_path(mock_netbox):
    mock_netbox.create.return_value = {"id": 42, "name": "test-site"}

    result = netbox_create_object(
        object_type="dcim.site",
        data={"name": "test-site", "slug": "test-site"},
    )

    mock_netbox.create.assert_called_once_with(
        "dcim/sites",
        {"name": "test-site", "slug": "test-site"},
        fallback_endpoint=None,
    )
    assert result == {"id": 42, "name": "test-site"}


@patch("netbox_mcp_server.server.netbox")
def test_create_object_invalid_type(mock_netbox):
    with pytest.raises(ValueError, match="Invalid object_type"):
        netbox_create_object(object_type="not.a.real.type", data={"name": "x"})
    mock_netbox.create.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_create_object_empty_data(mock_netbox):
    with pytest.raises(ValueError, match="non-empty"):
        netbox_create_object(object_type="dcim.site", data={})
    mock_netbox.create.assert_not_called()


@patch("netbox_mcp_server.server.NETBOX_OBJECT_TYPES")
@patch("netbox_mcp_server.server.netbox")
def test_create_object_passes_fallback_endpoint(mock_netbox, mock_types):
    """fallback_endpoint from NETBOX_OBJECT_TYPES is forwarded to the client."""
    mock_types.__contains__.return_value = True
    mock_types.__getitem__.return_value = {
        "endpoint": "vpn/tunnels",
        "fallback_endpoint": "plugins/vpn/tunnels",
    }
    mock_netbox.create.return_value = {"id": 1}

    netbox_create_object(object_type="vpn.tunnel", data={"name": "t"})

    mock_netbox.create.assert_called_once_with(
        "vpn/tunnels", {"name": "t"}, fallback_endpoint="plugins/vpn/tunnels"
    )


@patch("netbox_mcp_server.server.netbox")
def test_create_object_dry_run_returns_proposed_without_create(mock_netbox):
    """dry_run=True validates the request and never calls the client."""
    result = netbox_create_object(
        object_type="dcim.site",
        data={"name": "test-site", "slug": "test-site"},
        dry_run=True,
    )

    mock_netbox.create.assert_not_called()
    assert result == {
        "dry_run": True,
        "object_type": "dcim.site",
        "endpoint": "dcim/sites",
        "proposed": {"name": "test-site", "slug": "test-site"},
    }


@patch("netbox_mcp_server.server.netbox")
def test_create_object_dry_run_still_validates_type(mock_netbox):
    """dry_run does not bypass input validation."""
    with pytest.raises(ValueError, match="Invalid object_type"):
        netbox_create_object(object_type="not.real", data={"name": "x"}, dry_run=True)
    mock_netbox.create.assert_not_called()


@patch("netbox_mcp_server.server.write_denied_types", set(DEFAULT_WRITE_DENIED_TYPES))
@patch("netbox_mcp_server.server.netbox")
def test_create_object_dry_run_still_enforces_deny_list(mock_netbox):
    """dry_run does not bypass the write deny-list."""
    with pytest.raises(ValueError, match="deny-list"):
        netbox_create_object(
            object_type="users.token",
            data={"description": "x"},
            dry_run=True,
        )
    mock_netbox.create.assert_not_called()


# ============================================================================
# Update
# ============================================================================


@patch("netbox_mcp_server.server.netbox")
def test_update_object_happy_path(mock_netbox):
    mock_netbox.update.return_value = {"id": 7, "name": "renamed"}

    result = netbox_update_object(
        object_type="dcim.site",
        object_id=7,
        data={"name": "renamed"},
    )

    mock_netbox.update.assert_called_once_with(
        "dcim/sites", 7, {"name": "renamed"}, fallback_endpoint=None
    )
    assert result == {"id": 7, "name": "renamed"}


@patch("netbox_mcp_server.server.netbox")
def test_update_object_invalid_type(mock_netbox):
    with pytest.raises(ValueError, match="Invalid object_type"):
        netbox_update_object(object_type="not.real", object_id=1, data={"name": "x"})
    mock_netbox.update.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_update_object_empty_data(mock_netbox):
    with pytest.raises(ValueError, match="non-empty"):
        netbox_update_object(object_type="dcim.site", object_id=1, data={})
    mock_netbox.update.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_update_object_dry_run_returns_diff_without_patch(mock_netbox):
    """dry_run=True fetches the current object and never calls update."""
    mock_netbox.get.return_value = {
        "id": 7,
        "name": "old",
        "description": "unchanged",
    }

    result = netbox_update_object(
        object_type="dcim.site",
        object_id=7,
        data={"name": "new"},
        dry_run=True,
    )

    mock_netbox.get.assert_called_once_with("dcim/sites", id=7, fallback_endpoint=None)
    mock_netbox.update.assert_not_called()
    assert result == {
        "dry_run": True,
        "object_type": "dcim.site",
        "object_id": 7,
        "current": {"name": "old"},
        "proposed": {"name": "new"},
    }


# ============================================================================
# Delete
# ============================================================================


@patch("netbox_mcp_server.server.netbox")
def test_delete_object_happy_path(mock_netbox):
    mock_netbox.delete.return_value = True

    result = netbox_delete_object(object_type="dcim.site", object_id=99, confirm=True)

    mock_netbox.delete.assert_called_once_with("dcim/sites", 99, fallback_endpoint=None)
    assert result == {"deleted": True, "object_type": "dcim.site", "object_id": 99}


@patch("netbox_mcp_server.server.netbox")
def test_delete_object_requires_confirm(mock_netbox):
    """Without confirm=True, delete refuses and never hits the client."""
    with pytest.raises(ValueError, match="confirm=True"):
        netbox_delete_object(object_type="dcim.site", object_id=99)
    mock_netbox.delete.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_delete_object_raises_when_client_returns_false(mock_netbox):
    """Non-204 success must surface as an error, not a silent 'deleted: True'."""
    mock_netbox.delete.return_value = False

    with pytest.raises(RuntimeError, match="non-204"):
        netbox_delete_object(object_type="dcim.site", object_id=99, confirm=True)


@patch("netbox_mcp_server.server.netbox")
def test_delete_object_invalid_type(mock_netbox):
    with pytest.raises(ValueError, match="Invalid object_type"):
        netbox_delete_object(object_type="not.real", object_id=1, confirm=True)
    mock_netbox.delete.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_delete_object_dry_run_returns_target_without_deleting(mock_netbox):
    """dry_run=True fetches the target and never calls delete (confirm irrelevant)."""
    mock_netbox.get.return_value = {"id": 99, "name": "doomed"}

    result = netbox_delete_object(object_type="dcim.site", object_id=99, dry_run=True)

    mock_netbox.get.assert_called_once_with("dcim/sites", id=99, fallback_endpoint=None)
    mock_netbox.delete.assert_not_called()
    assert result == {
        "dry_run": True,
        "object_type": "dcim.site",
        "object_id": 99,
        "target": {"id": 99, "name": "doomed"},
    }


# ============================================================================
# Error translation
# ============================================================================


@patch("netbox_mcp_server.server.netbox")
def test_http_error_translated_to_value_error_with_json_body(mock_netbox):
    response = MagicMock(spec=httpx.Response)
    response.status_code = 400
    response.json.return_value = {"name": ["This field is required."]}
    mock_netbox.create.side_effect = httpx.HTTPStatusError(
        "400 Bad Request", request=MagicMock(), response=response
    )

    with pytest.raises(ValueError, match="This field is required"):
        netbox_create_object(object_type="dcim.site", data={"slug": "x"})


@patch("netbox_mcp_server.server.netbox")
def test_http_error_falls_back_to_text_when_body_not_json(mock_netbox):
    response = MagicMock(spec=httpx.Response)
    response.status_code = 500
    response.json.side_effect = ValueError("not json")
    response.text = "Internal Server Error"
    mock_netbox.update.side_effect = httpx.HTTPStatusError(
        "500 Server Error", request=MagicMock(), response=response
    )

    with pytest.raises(ValueError, match="Internal Server Error"):
        netbox_update_object(object_type="dcim.site", object_id=1, data={"name": "x"})


# ============================================================================
# Write deny-list (defense-in-depth)
# ============================================================================


@pytest.mark.parametrize(
    "denied_type",
    [
        # Credentials and permissions.
        "users.token",
        "users.user",
        # Code execution and outbound callbacks.
        "extras.webhook",
        "extras.script",
        "extras.eventrule",
        # Server-rendered Jinja2.
        "extras.configtemplate",
        "extras.exporttemplate",
        # Ingestion path for scripts and templates.
        "core.datasource",
        # Destroys field data across every object of its type.
        "extras.customfield",
    ],
)
@patch("netbox_mcp_server.server.write_denied_types", set(DEFAULT_WRITE_DENIED_TYPES))
@patch("netbox_mcp_server.server.netbox")
def test_create_denied_type_refused_by_default(mock_netbox, denied_type):
    """Security-critical types are refused by the default write deny-list."""
    with pytest.raises(ValueError, match="deny-list"):
        netbox_create_object(object_type=denied_type, data={"name": "x"})
    mock_netbox.create.assert_not_called()


@pytest.mark.parametrize(
    "denied_type",
    ["extras.configtemplate", "extras.exporttemplate", "core.datasource", "extras.customfield"],
)
def test_newly_denied_types_are_real_registry_entries(denied_type):
    """A deny-list entry only protects anything if it matches a writable type."""
    assert denied_type in NETBOX_OBJECT_TYPES


@patch("netbox_mcp_server.server.write_denied_types", set(DEFAULT_WRITE_DENIED_TYPES))
@patch("netbox_mcp_server.server.netbox")
def test_update_denied_type_refused_by_default(mock_netbox):
    with pytest.raises(ValueError, match="deny-list"):
        netbox_update_object(object_type="users.token", object_id=1, data={"key": "x"})
    mock_netbox.update.assert_not_called()


@patch("netbox_mcp_server.server.write_denied_types", set(DEFAULT_WRITE_DENIED_TYPES))
@patch("netbox_mcp_server.server.netbox")
def test_delete_denied_type_refused_before_confirm(mock_netbox):
    """The deny-list is checked even with confirm=True and before any client call."""
    with pytest.raises(ValueError, match="deny-list"):
        netbox_delete_object(object_type="extras.webhook", object_id=1, confirm=True)
    mock_netbox.delete.assert_not_called()


@patch("netbox_mcp_server.server.write_denied_types", set())
@patch("netbox_mcp_server.server.netbox")
def test_denied_type_allowed_when_denylist_overridden(mock_netbox):
    """An operator can override the deny-list (e.g. WRITE_DENIED_TYPES=[])."""
    mock_netbox.create.return_value = {"id": 1}

    result = netbox_create_object(object_type="users.token", data={"key": "x"})

    assert result == {"id": 1}
    mock_netbox.create.assert_called_once()


# ============================================================================
# Ambiguous write outcomes (sent, but unanswered)
#
# A transport failure AFTER the request was sent leaves no way to distinguish a
# committed write from a lost one. Raising the bare httpx error is harmful:
# str(httpx.ReadTimeout("")) is "", so the model sees an empty message and the
# obvious next move is a retry — which duplicates rows for types with no
# uniqueness constraint (ipam.prefix, dcim.cable, ipam.service).
# ============================================================================

POST_SEND_ERRORS = [
    httpx.ReadTimeout(""),
    httpx.WriteTimeout(""),
    httpx.ReadError("connection reset"),
    httpx.WriteError("broken pipe"),
    httpx.RemoteProtocolError("server disconnected"),
]

PRE_SEND_ERRORS = [
    httpx.ConnectError("connection refused"),
    httpx.ConnectTimeout(""),
    httpx.ProxyError("proxy refused"),
    httpx.PoolTimeout(""),
]


@pytest.mark.parametrize("exc", POST_SEND_ERRORS, ids=lambda e: type(e).__name__)
@patch("netbox_mcp_server.server.write_denied_types", set())
@patch("netbox_mcp_server.server.netbox")
def test_create_post_send_failure_warns_outcome_unknown(mock_netbox, exc):
    """A sent-but-unanswered create must say it may have committed."""
    mock_netbox.create.side_effect = exc

    with pytest.raises(RuntimeError, match="MAY have been committed") as excinfo:
        netbox_create_object(object_type="ipam.prefix", data={"prefix": "10.0.0.0/24"})

    message = str(excinfo.value)
    # The message must be actionable, not empty like the underlying httpx error.
    assert "Do NOT retry" in message
    assert type(exc).__name__ in message
    assert excinfo.value.__cause__ is exc


@pytest.mark.parametrize("exc", POST_SEND_ERRORS, ids=lambda e: type(e).__name__)
@patch("netbox_mcp_server.server.write_denied_types", set())
@patch("netbox_mcp_server.server.netbox")
def test_update_post_send_failure_warns_outcome_unknown(mock_netbox, exc):
    mock_netbox.update.side_effect = exc

    with pytest.raises(RuntimeError, match="MAY have been committed") as excinfo:
        netbox_update_object(object_type="ipam.prefix", object_id=7, data={"status": "active"})

    assert "id=7" in str(excinfo.value)


@pytest.mark.parametrize("exc", POST_SEND_ERRORS, ids=lambda e: type(e).__name__)
@patch("netbox_mcp_server.server.write_denied_types", set())
@patch("netbox_mcp_server.server.netbox")
def test_delete_post_send_failure_warns_outcome_unknown(mock_netbox, exc):
    mock_netbox.delete.side_effect = exc

    with pytest.raises(RuntimeError, match="MAY have been committed") as excinfo:
        netbox_delete_object(object_type="ipam.prefix", object_id=7, confirm=True)

    assert "id=7" in str(excinfo.value)


@pytest.mark.parametrize("exc", PRE_SEND_ERRORS, ids=lambda e: type(e).__name__)
@patch("netbox_mcp_server.server.write_denied_types", set())
@patch("netbox_mcp_server.server.netbox")
def test_pre_send_failures_propagate_unchanged(mock_netbox, exc):
    """A failure before the request left the client is safe to retry.

    These must NOT be relabelled as ambiguous — doing so would tell the caller to
    go verify state after a write that provably never happened.
    """
    mock_netbox.create.side_effect = exc

    with pytest.raises(type(exc)):
        netbox_create_object(object_type="ipam.prefix", data={"prefix": "10.0.0.0/24"})


@patch("netbox_mcp_server.server.write_denied_types", set())
@patch("netbox_mcp_server.server.netbox")
def test_bare_httpx_timeout_message_would_have_been_empty(mock_netbox):
    """Regression guard for why this handling exists at all."""
    assert str(httpx.ReadTimeout("")) == ""

    mock_netbox.create.side_effect = httpx.ReadTimeout("")
    with pytest.raises(RuntimeError) as excinfo:
        netbox_create_object(object_type="ipam.prefix", data={"prefix": "10.0.0.0/24"})

    assert str(excinfo.value).strip()


@patch("netbox_mcp_server.server.write_denied_types", set())
@patch("netbox_mcp_server.server.netbox")
def test_http_status_error_still_surfaces_netbox_detail(mock_netbox):
    """The ambiguous-outcome clauses must not shadow 4xx field-level errors."""
    response = httpx.Response(400, json={"prefix": ["Invalid prefix format."]})
    mock_netbox.create.side_effect = httpx.HTTPStatusError(
        "400", request=MagicMock(), response=response
    )

    with pytest.raises(ValueError, match="Invalid prefix format"):
        netbox_create_object(object_type="ipam.prefix", data={"prefix": "nope"})
