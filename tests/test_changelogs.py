"""Tests for netbox_get_changelogs filter validation and pagination cap.

The changelog tool is the primary audit surface once writes are enabled, so it
must validate filters (like netbox_get_objects) and bound its own page size
rather than passing an arbitrary filters dict straight through.
"""

from unittest.mock import patch

import pytest

from netbox_mcp_server.server import netbox_get_changelogs


@patch("netbox_mcp_server.server.netbox")
def test_changelogs_rejects_invalid_filter(mock_netbox):
    """Filters go through validate_filters, like netbox_get_objects."""
    with pytest.raises(ValueError, match="__in"):
        netbox_get_changelogs(filters={"changed_object_id__in": [1, 2]})
    mock_netbox.get.assert_not_called()


@patch("netbox_mcp_server.server.netbox")
def test_changelogs_applies_default_pagination(mock_netbox):
    mock_netbox.get.return_value = {"count": 0, "results": []}

    netbox_get_changelogs(filters={"action": "delete"})

    params = mock_netbox.get.call_args[1]["params"]
    assert params["limit"] == 5
    assert params["offset"] == 0
    # Original filter is preserved alongside the pagination params.
    assert params["action"] == "delete"


@patch("netbox_mcp_server.server.netbox")
def test_changelogs_filter_cannot_override_limit_cap(mock_netbox):
    """A limit smuggled into filters is overridden by the capped parameter."""
    mock_netbox.get.return_value = {"count": 0, "results": []}

    netbox_get_changelogs(filters={"limit": 100000}, limit=10)

    params = mock_netbox.get.call_args[1]["params"]
    assert params["limit"] == 10
