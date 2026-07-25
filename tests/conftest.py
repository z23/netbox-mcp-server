"""Shared fixtures restoring the module-level state that main() mutates.

server.main() is not a pure function: it assigns the module globals `netbox` and
`write_denied_types` (declared global at the top of main()), mutates
NETBOX_OBJECT_TYPES in place when plugin discovery is enabled, and registers the
three write tools on the shared module-level FastMCP instance. None of that is
undone, so any test that calls main() changes the environment for every test that
runs after it.

That produced two order-dependent failures before this file existed:

1. test_module_level_mcp_has_no_write_tools_at_import passed only because it is
   defined above the tests that call main(). Selecting node IDs in the other
   order, or --lf, or xdist sharding, made it fail. It is the regression guard for
   someone adding @mcp.tool to a write function, so a false result there is the
   expensive kind.
2. main() left write_denied_types as set() — the deny-list fully disarmed. Every
   deny-list test happens to re-patch it, so this was invisible; the first test
   that did not would have passed vacuously.

The autouse fixture makes both impossible regardless of test order.
"""

import contextlib

import pytest

from netbox_mcp_server import server as server_module
from netbox_mcp_server.netbox_types import NETBOX_OBJECT_TYPES

WRITE_TOOL_NAMES = (
    "netbox_create_object",
    "netbox_update_object",
    "netbox_delete_object",
)


@pytest.fixture(autouse=True)
def restore_server_module_state():
    """Snapshot and restore every piece of global state main() touches."""
    original_netbox = server_module.netbox
    original_denied = set(server_module.write_denied_types)
    original_object_types = dict(NETBOX_OBJECT_TYPES)

    yield

    server_module.netbox = original_netbox
    server_module.write_denied_types = original_denied

    # Mutated in place by main() via NETBOX_OBJECT_TYPES.update(plugin_types),
    # so rebinding is not enough — the dict object itself must be reset.
    NETBOX_OBJECT_TYPES.clear()
    NETBOX_OBJECT_TYPES.update(original_object_types)

    # Write tools are registered on the shared instance and must not persist into
    # the next test. local_provider.remove_tool raises KeyError when the tool is
    # absent, which is the common case, so suppress that rather than probing first
    # (the presence check is async). mcp.remove_tool() is deprecated in FastMCP 3.
    for tool_name in WRITE_TOOL_NAMES:
        with contextlib.suppress(KeyError):
            server_module.mcp.local_provider.remove_tool(tool_name)
