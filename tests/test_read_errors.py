"""Tests that read tools surface NetBox's error body, not just a status code.

NetBox returns field-level detail in 4xx bodies, e.g.
{"detail": "Invalid filter field: sight"}. Without it the caller sees only
httpx's generic "Client error '400 Bad Request' for url ..." and has nothing to
correct, so it retries the same broken call. The write tools already did this via
_httpx_error_to_value_error; the always-registered read tools did not.
"""

from unittest.mock import MagicMock, patch

import httpx
import pytest

from netbox_mcp_server.server import (
    netbox_get_changelogs,
    netbox_get_object_by_id,
    netbox_get_objects,
)


def _status_error(status: int, payload: dict) -> httpx.HTTPStatusError:
    return httpx.HTTPStatusError(
        f"{status}", request=MagicMock(), response=httpx.Response(status, json=payload)
    )


@patch("netbox_mcp_server.server.netbox")
def test_get_objects_surfaces_netbox_detail(mock_netbox):
    mock_netbox.get.side_effect = _status_error(400, {"detail": "Invalid filter field: sight"})

    with pytest.raises(ValueError, match="Invalid filter field: sight"):
        netbox_get_objects(object_type="dcim.device", filters={"sight": "dc1"})


@patch("netbox_mcp_server.server.netbox")
def test_get_objects_includes_status_code(mock_netbox):
    mock_netbox.get.side_effect = _status_error(400, {"detail": "nope"})

    with pytest.raises(ValueError, match="400"):
        netbox_get_objects(object_type="dcim.device", filters={})


@patch("netbox_mcp_server.server.netbox")
def test_get_object_by_id_surfaces_netbox_detail(mock_netbox):
    mock_netbox.get.side_effect = _status_error(404, {"detail": "Not found."})

    with pytest.raises(ValueError, match="Not found"):
        netbox_get_object_by_id(object_type="dcim.device", object_id=99999)


@patch("netbox_mcp_server.server.netbox")
def test_get_changelogs_surfaces_netbox_detail(mock_netbox):
    mock_netbox.get.side_effect = _status_error(400, {"detail": "Invalid filter field: acton"})

    with pytest.raises(ValueError, match="Invalid filter field: acton"):
        netbox_get_changelogs(filters={"acton": "update"})


@patch("netbox_mcp_server.server.netbox")
def test_field_level_errors_are_preserved_not_flattened(mock_netbox):
    """NetBox's per-field dict must reach the caller, not be reduced to a status."""
    mock_netbox.get.side_effect = _status_error(
        400, {"status": ["Select a valid choice."], "site": ["Invalid pk."]}
    )

    with pytest.raises(ValueError, match="Select a valid choice") as excinfo:
        netbox_get_objects(object_type="dcim.device", filters={"status": "bogus"})

    # Both fields must survive, not just the one matched above.
    assert "Invalid pk" in str(excinfo.value)


@patch("netbox_mcp_server.server.netbox")
def test_non_json_error_body_still_surfaces_text(mock_netbox):
    """A proxy returning HTML must not crash the error path."""
    mock_netbox.get.side_effect = httpx.HTTPStatusError(
        "502",
        request=MagicMock(),
        response=httpx.Response(502, text="<html>Bad Gateway</html>"),
    )

    with pytest.raises(ValueError, match="Bad Gateway"):
        netbox_get_objects(object_type="dcim.device", filters={})


@patch("netbox_mcp_server.server.netbox")
def test_transport_errors_are_not_converted_to_value_error(mock_netbox):
    """Only HTTP status errors carry a body; NetBox being unreachable must not be
    relabelled as a caller input error."""
    mock_netbox.get.side_effect = httpx.ConnectError("connection refused")

    with pytest.raises(httpx.ConnectError):
        netbox_get_objects(object_type="dcim.device", filters={})
