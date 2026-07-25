import argparse
import asyncio
import hashlib
import hmac
import logging
import sys
from typing import Annotated, Any

import httpx
from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, TokenVerifier
from pydantic import Field, SecretStr
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

from netbox_mcp_server.config import (
    DEFAULT_WRITE_DENIED_TYPES,
    Settings,
    configure_logging,
)
from netbox_mcp_server.netbox_client import NetBoxRestClient
from netbox_mcp_server.netbox_types import NETBOX_OBJECT_TYPES


def parse_cli_args() -> dict[str, Any]:
    """
    Parse command-line arguments for configuration overrides.

    Returns:
        dict of configuration overrides (only includes explicitly set values)
    """
    parser = argparse.ArgumentParser(
        description="NetBox MCP Server - Model Context Protocol server for NetBox",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Core NetBox settings
    parser.add_argument(
        "--netbox-url",
        type=str,
        help="Base URL of the NetBox instance (e.g., https://netbox.example.com/)",
    )
    parser.add_argument(
        "--netbox-token",
        type=str,
        help="API token for NetBox authentication (prefer the NETBOX_TOKEN env var)",
    )
    parser.add_argument(
        "--netbox-timeout",
        type=float,
        help="Per-request timeout in seconds for NetBox API calls (default: 30)",
    )

    # Transport settings
    parser.add_argument(
        "--transport",
        type=str,
        choices=["stdio", "http"],
        help="MCP transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host",
        type=str,
        help="Host address for HTTP server (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Port for HTTP server (default: 8000)",
    )
    parser.add_argument(
        "--cors-origins",
        action="append",
        help="CORS origins (repeat flag). Use * to allow any origin (default: none)",
    )
    parser.add_argument(
        "--mcp-auth-token",
        type=str,
        help=(
            "Bearer token required on the HTTP transport endpoint "
            "(prefer the MCP_AUTH_TOKEN env var; default: none)"
        ),
    )

    # Security settings
    ssl_group = parser.add_mutually_exclusive_group()
    ssl_group.add_argument(
        "--verify-ssl",
        action="store_true",
        dest="verify_ssl",
        default=None,
        help="Verify SSL certificates (default)",
    )
    ssl_group.add_argument(
        "--no-verify-ssl",
        action="store_false",
        dest="verify_ssl",
        help="Disable SSL certificate verification (not recommended)",
    )

    # Plugin discovery settings
    parser.add_argument(
        "--enable-plugin-discovery",
        action="store_true",
        default=None,
        dest="enable_plugin_discovery",
        help="Auto-discover plugin object types from NetBox at startup",
    )

    # Write tool settings
    parser.add_argument(
        "--enable-writes",
        action="store_true",
        default=None,
        dest="enable_writes",
        help="Register create/update/delete tools (requires NetBox token with write perms)",
    )
    parser.add_argument(
        "--write-denied-types",
        action="append",
        dest="write_denied_types",
        help=(
            "Object type the write tools refuse to mutate (repeat flag). Entries ending "
            "in '.*' match a whole app label. Replaces the default deny-list."
        ),
    )
    parser.add_argument(
        "--allow-unauthenticated-writes",
        action="store_true",
        default=None,
        dest="allow_unauthenticated_writes",
        help=(
            "Permit writes on the HTTP transport with no MCP_AUTH_TOKEN "
            "(trusted localhost only; otherwise the server refuses to start)"
        ),
    )

    # Observability settings
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging verbosity level (default: INFO)",
    )

    args: argparse.Namespace = parser.parse_args()

    overlay: dict[str, Any] = {}
    if args.netbox_url is not None:
        overlay["netbox_url"] = args.netbox_url
    if args.netbox_token is not None:
        overlay["netbox_token"] = args.netbox_token
    if args.netbox_timeout is not None:
        overlay["netbox_timeout"] = args.netbox_timeout
    if args.transport is not None:
        overlay["transport"] = args.transport
    if args.host is not None:
        overlay["host"] = args.host
    if args.port is not None:
        overlay["port"] = args.port
    if args.cors_origins is not None:
        overlay["cors_origins"] = args.cors_origins
    if args.mcp_auth_token is not None:
        overlay["mcp_auth_token"] = args.mcp_auth_token
    if args.verify_ssl is not None:
        overlay["verify_ssl"] = args.verify_ssl
    if args.enable_plugin_discovery is not None:
        overlay["enable_plugin_discovery"] = args.enable_plugin_discovery
    if args.enable_writes is not None:
        overlay["enable_writes"] = args.enable_writes
    if args.write_denied_types is not None:
        overlay["write_denied_types"] = args.write_denied_types
    if args.allow_unauthenticated_writes is not None:
        overlay["allow_unauthenticated_writes"] = args.allow_unauthenticated_writes
    if args.log_level is not None:
        overlay["log_level"] = args.log_level

    return overlay


class BearerTokenVerifier(TokenVerifier):
    """Constant-time single-secret bearer check for the HTTP transport.

    This is a FastMCP Resource Server verifier: it only validates an incoming
    'Authorization: Bearer <token>' against one configured secret and issues no
    tokens itself. FastMCP mounts its own auth middleware around this, returning
    401 (+ WWW-Authenticate) for unauthenticated requests to the MCP endpoint.
    """

    def __init__(self, secret: str) -> None:
        super().__init__()
        # Digest, not raw secret: lets verify_token compare in constant time.
        self._secret_digest = hashlib.sha256(secret.encode("utf-8")).digest()

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return an AccessToken for a matching bearer, or None to reject."""
        if not token:
            return None
        # Hash both sides: compare_digest raises TypeError on a non-ASCII str, and
        # the bearer is attacker-controlled (header bytes decode as latin-1).
        token_digest = hashlib.sha256(token.encode("utf-8", "surrogatepass")).digest()
        if not hmac.compare_digest(token_digest, self._secret_digest):
            return None
        return AccessToken(token=token, client_id="netbox-mcp-server", scopes=[])


def build_http_auth(token: SecretStr | None) -> TokenVerifier | None:
    """
    Build the HTTP transport auth provider from an optional bearer token.

    Returns a verifier that makes FastMCP reject unauthenticated requests to the
    MCP endpoint with 401, or None when no token is configured. Empty or
    whitespace-only values are normalized to None upstream in Settings, so a
    non-None token here is always a real secret.

    Args:
        token: Optional bearer token to require on the HTTP transport endpoint

    Returns:
        A TokenVerifier requiring the token, or None when no token is set
    """
    if token is None:
        return None
    return BearerTokenVerifier(token.get_secret_value())


# Default object types for global search
DEFAULT_SEARCH_TYPES = [
    "dcim.device",  # Most common search target
    "dcim.site",  # Site names frequently searched
    "ipam.ipaddress",  # IP searches very common
    "dcim.interface",  # Interface names/descriptions
    "dcim.rack",  # Rack identifiers
    "ipam.vlan",  # VLAN names/IDs
    "circuits.circuit",  # Circuit identifiers
    "virtualization.virtualmachine",  # VM names
]

# Reserved key in netbox_search_objects' result carrying per-type errors and
# truncation notices. Object types are always "app.model", so this cannot collide.
SEARCH_META_KEY = "_meta"

mcp = FastMCP("NetBox")
netbox = None

# Object types the write tools refuse to mutate (defense-in-depth on top of NetBox
# token scoping). Seeded with the safe default so an unwired import still denies;
# main() overrides this from settings.write_denied_types.
write_denied_types: set[str] = set(DEFAULT_WRITE_DENIED_TYPES)


def _ensure_write_allowed(object_type: str) -> None:
    """Reject writes to security-critical object types.

    The primary control is NetBox API-token scoping; this is a server-side backstop
    so a broadly-scoped token combined with prompt injection cannot mint credentials,
    grant permissions, or point webhooks/scripts at an attacker. An entry in the
    deny-list ending in ".*" matches a whole app label (e.g. "users.*").

    Args:
        object_type: The NetBox object type being mutated (e.g. "dcim.device")

    Raises:
        ValueError: If the object type is in the configured write deny-list.
    """
    app_label = object_type.split(".", 1)[0]
    if object_type in write_denied_types or f"{app_label}.*" in write_denied_types:
        raise ValueError(
            f"Refusing to write '{object_type}': this object type is in the write "
            "deny-list because mutating it is security-critical. Override via the "
            "WRITE_DENIED_TYPES setting only if you intentionally need to mutate it."
        )


def validate_filters(filters: dict) -> None:
    """
    Validate that filters don't use unsupported lookup suffixes or multi-hop
    relationship traversal.

    NetBox API does not support:
    - __in suffix (pass a list as the field value instead: {'id': [1, 2, 3]})
    - nested relationship queries like device__site_id or interface__device__site

    Valid patterns:
    - Direct field filters: site_id, name, status
    - List values for multi-value filters: {'site_id': [1, 2]}
    - Lookup expressions supported by the target NetBox field: name__ic, id__gt

    Args:
        filters: Dictionary of filter parameters

    Raises:
        ValueError: If filter uses an unsupported lookup suffix or multi-hop
                    relationship traversal
    """
    valid_suffixes = {
        "n",
        "ic",
        "nic",
        "isw",
        "nisw",
        "iew",
        "niew",
        "ie",
        "nie",
        "empty",
        "regex",
        "iregex",
        "lt",
        "lte",
        "gt",
        "gte",
    }

    for filter_name in filters:
        # Skip special parameters
        if filter_name in ("limit", "offset", "fields", "q"):
            continue

        if "__" not in filter_name:
            continue

        parts = filter_name.split("__")

        if len(parts) == 2 and parts[-1] == "in":
            base = parts[0]
            raise ValueError(
                f"Invalid filter '{filter_name}': '__in' lookup suffix is not "
                "supported and may be silently ignored by NetBox. "
                f"Pass a list to the field directly instead: {{'{base}': [1, 2, 3]}}"
            )

        # Allow field__suffix pattern (e.g., name__ic, id__gt)
        if len(parts) == 2 and parts[-1] in valid_suffixes:
            continue
        # Block multi-hop patterns and invalid suffixes
        if len(parts) >= 2:
            raise ValueError(
                f"Invalid filter '{filter_name}': Multi-hop relationship "
                f"traversal or invalid lookup suffix not supported. Use direct field filters like "
                f"'site_id' or two-step queries."
            )


@mcp.tool(
    description="""
    Get objects from NetBox based on their type and filters

    Args:
        object_type: String representing the NetBox object type (e.g. "dcim.device", "ipam.ipaddress")
        filters: dict of filters to apply to the API call based on the NetBox API filtering options

                FILTER RULES:
                Valid: Direct fields like {'site_id': 1, 'name': 'router', 'status': 'active'}
                Valid: Field-supported lookups like {'name__ic': 'switch', 'vid__gte': 100}
                Invalid: Multi-hop like {'device__site_id': 1} - NOT supported

                Lookup suffixes: n, ic, nic, isw, nisw, iew, niew, ie, nie,
                                 empty, regex, iregex, lt, lte, gt, gte
                Lookup support is field-specific. NetBox may silently ignore unsupported
                lookups and return overly broad results. The '__in' suffix is not supported
                and is rejected by this tool. For multiple values, pass a list as the field
                value directly: {'vminterface_id': [621493, 631527]} or {'id': [1, 2, 3]}.

                Two-step pattern for cross-relationship queries:
                  sites = netbox_get_objects('dcim.site', {'name': 'NYC'})
                  netbox_get_objects('dcim.device', {'site_id': sites[0]['id']})

        fields: Optional list of specific fields to return
                **IMPORTANT: ALWAYS USE THIS PARAMETER TO MINIMIZE TOKEN USAGE**
                Field filtering significantly reduces response payload and is critical for performance.

                - None or [] = returns all fields (NOT RECOMMENDED - use only when you need complete objects)
                - ['id', 'name'] = returns only specified fields (RECOMMENDED)

                Examples:
                - For counting: ['id'] (minimal payload)
                - For listings: ['id', 'name', 'status']
                - For IP addresses: ['address', 'dns_name', 'description']

                Uses NetBox's native field filtering via ?fields= parameter.
                **Always specify only the fields you actually need.**

        brief: returns only a minimal representation of each object in the response.
               This is useful when you need only a list of available objects without any related data.

        limit: Maximum results to return (default 5, max 100)
               Start with default, increase only if needed

        offset: Skip this many results for pagination (default 0)
                Example: offset=0 (page 1), offset=5 (page 2), offset=10 (page 3)

        ordering: Fields used to determine sort order of results.
                  Field names may be prefixed with '-' to invert the sort order.
                  Multiple fields may be specified with a list of strings.

                  Examples:
                  - 'name' (alphabetical by name)
                  - '-id' (ordered by ID descending)
                  - ['facility', '-name'] (by facility, then by name descending)
                  - None, '' or [] (default NetBox ordering)


    Returns:
        Paginated response dict with the following structure:
            - count: Total number of objects matching the query
                     ALWAYS REFER TO THIS FIELD FOR THE TOTAL NUMBER OF OBJECTS MATCHING THE QUERY
            - next: URL to next page (or null if no more pages)
                    ALWAYS REFER TO THIS FIELD FOR THE NEXT PAGE OF RESULTS
            - previous: URL to previous page (or null if on first page)
                        ALWAYS REFER TO THIS FIELD FOR THE PREVIOUS PAGE OF RESULTS
            - results: Array of objects for this page
                       ALWAYS REFER TO THIS FIELD FOR THE OBJECTS ON THIS PAGE

    ENSURE YOU ARE AWARE THE RESULTS ARE PAGINATED BEFORE PROVIDING RESPONSE TO THE USER.

    Valid object_type values:

    """
    + "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
    + """

    See NetBox API documentation for filtering options for each object type.
    """
)
def netbox_get_objects(
    object_type: str,
    filters: dict,
    fields: list[str] | None = None,
    brief: bool = False,
    limit: Annotated[int, Field(default=5, ge=1, le=100)] = 5,
    offset: Annotated[int, Field(default=0, ge=0)] = 0,
    ordering: str | list[str] | None = None,
):
    """
    Get objects from NetBox based on their type and filters
    """
    # Validate object_type exists in mapping
    if object_type not in NETBOX_OBJECT_TYPES:
        valid_types = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
        raise ValueError(f"Invalid object_type. Must be one of:\n{valid_types}")

    # Validate filter patterns
    validate_filters(filters)

    # Get API endpoint and fallback from mapping
    endpoint, fallback = _get_endpoint_info(object_type)

    # Build params with pagination (parameters override filters dict)
    params = filters.copy()
    params["limit"] = limit
    params["offset"] = offset

    if fields:
        params["fields"] = ",".join(fields)

    if brief:
        params["brief"] = "1"

    if ordering:
        if isinstance(ordering, list):
            ordering = ",".join(ordering)
        if ordering.strip() != "":
            params["ordering"] = ordering

    # Make API call
    return netbox.get(endpoint, params=params, fallback_endpoint=fallback)


@mcp.tool
def netbox_get_object_by_id(
    object_type: str,
    object_id: Annotated[int, Field(ge=1)],
    fields: list[str] | None = None,
    brief: bool = False,
):
    """
    Get detailed information about a specific NetBox object by its ID.

    Args:
        object_type: String representing the NetBox object type (e.g. "dcim.device", "ipam.ipaddress")
        object_id: The numeric ID of the object
        fields: Optional list of specific fields to return
                **IMPORTANT: ALWAYS USE THIS PARAMETER TO MINIMIZE TOKEN USAGE**
                Field filtering reduces response payload by 80-90% and is critical for performance.

                - None or [] = returns all fields (NOT RECOMMENDED - use only when you need complete objects)
                - ['id', 'name'] = returns only specified fields (RECOMMENDED)

                Examples:
                - For basic info: ['id', 'name', 'status']
                - For devices: ['id', 'name', 'status', 'site']
                - For IP addresses: ['address', 'dns_name', 'vrf', 'status']

                Uses NetBox's native field filtering via ?fields= parameter.
                **Always specify only the fields you actually need.**
        brief: returns only a minimal representation of the object in the response.
               This is useful when you need only a summary of the object without any related data.

    Returns:
        Object dict (complete or with only requested fields based on fields parameter)
    """
    # Validate object_type exists in mapping
    if object_type not in NETBOX_OBJECT_TYPES:
        valid_types = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
        raise ValueError(f"Invalid object_type. Must be one of:\n{valid_types}")

    # Get API endpoint and fallback from mapping
    endpoint, fallback = _get_endpoint_info(object_type)
    full_endpoint = f"{endpoint}/{object_id}"
    full_fallback = f"{fallback}/{object_id}" if fallback else None

    params = {}
    if fields:
        params["fields"] = ",".join(fields)

    if brief:
        params["brief"] = "1"

    return netbox.get(full_endpoint, params=params, fallback_endpoint=full_fallback)


def _httpx_error_to_value_error(exc: httpx.HTTPStatusError) -> ValueError:
    """Convert an httpx.HTTPStatusError into a ValueError including NetBox's response body.

    NetBox returns structured field-level errors in 4xx response bodies
    (e.g. {"name": ["This field is required."]}). Surfacing that detail to the
    LLM gives it enough context to retry the call with corrected input.
    """
    try:
        detail: Any = exc.response.json()
    except ValueError:
        detail = exc.response.text[:500]
    return ValueError(f"NetBox API error {exc.response.status_code}: {detail}")


def netbox_create_object(
    object_type: str,
    data: dict[str, Any],
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Create a new object in NetBox.

    Args:
        object_type: String representing the NetBox object type (e.g. "dcim.device", "ipam.ipaddress")
        data: Field values for the new object. Required fields depend on the object type;
              consult NetBox API docs or call netbox_get_objects to see existing examples.
              Foreign keys generally accept either a numeric id or a natural slug.
        dry_run: If True, validate the request and return the intended payload without
                 sending the POST. Use this to preview a create before committing to it.

    Returns:
        On a real call: the created object as a dict (includes server-assigned id, url, created, etc.).
        On dry_run: {"dry_run": True, "object_type": ..., "endpoint": ..., "proposed": <data>}.
    """
    if object_type not in NETBOX_OBJECT_TYPES:
        valid_types = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
        raise ValueError(f"Invalid object_type. Must be one of:\n{valid_types}")

    _ensure_write_allowed(object_type)

    if not data:
        raise ValueError("data must be a non-empty dict")

    logger = logging.getLogger(__name__)
    endpoint, fallback = _get_endpoint_info(object_type)

    if dry_run:
        logger.info(f"netbox_create_object[dry_run]: {object_type} fields={sorted(data.keys())}")
        return {
            "dry_run": True,
            "object_type": object_type,
            "endpoint": endpoint,
            "proposed": data,
        }

    logger.info(f"netbox_create_object: {object_type} fields={sorted(data.keys())}")
    try:
        result = netbox.create(endpoint, data, fallback_endpoint=fallback)
    except httpx.HTTPStatusError as e:
        raise _httpx_error_to_value_error(e) from e
    logger.info(f"netbox_create_object: {object_type} created id={result.get('id')}")
    return result


def netbox_update_object(
    object_type: str,
    object_id: Annotated[int, Field(ge=1)],
    data: dict[str, Any],
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Partial update (PATCH) of an existing NetBox object.

    Args:
        object_type: String representing the NetBox object type (e.g. "dcim.device")
        object_id: The numeric ID of the object to update
        data: Fields to change. PATCH semantics — only listed fields are modified;
              omitted fields are left as-is.
        dry_run: If True, fetch the current object and return the intended diff
                 without sending the PATCH. Use this to preview a change before
                 committing to it.

    Returns:
        On a real call: the updated object as a dict.
        On dry_run: {"dry_run": True, "object_type": ..., "object_id": ...,
                     "current": <subset of current values for the changed fields>,
                     "proposed": <data>}.
    """
    if object_type not in NETBOX_OBJECT_TYPES:
        valid_types = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
        raise ValueError(f"Invalid object_type. Must be one of:\n{valid_types}")

    _ensure_write_allowed(object_type)

    if not data:
        raise ValueError("data must be a non-empty dict")

    logger = logging.getLogger(__name__)
    endpoint, fallback = _get_endpoint_info(object_type)

    if dry_run:
        logger.info(
            f"netbox_update_object[dry_run]: {object_type} id={object_id} "
            f"fields={sorted(data.keys())}"
        )
        try:
            current = netbox.get(endpoint, id=object_id, fallback_endpoint=fallback)
        except httpx.HTTPStatusError as e:
            raise _httpx_error_to_value_error(e) from e
        current_subset = {k: current.get(k) for k in data}
        return {
            "dry_run": True,
            "object_type": object_type,
            "object_id": object_id,
            "current": current_subset,
            "proposed": data,
        }

    logger.info(f"netbox_update_object: {object_type} id={object_id} fields={sorted(data.keys())}")
    try:
        result = netbox.update(endpoint, object_id, data, fallback_endpoint=fallback)
    except httpx.HTTPStatusError as e:
        raise _httpx_error_to_value_error(e) from e
    logger.info(f"netbox_update_object: {object_type} id={object_id} updated")
    return result


def netbox_delete_object(
    object_type: str,
    object_id: Annotated[int, Field(ge=1)],
    confirm: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """
    Delete a NetBox object. Cannot be undone.

    Args:
        object_type: String representing the NetBox object type (e.g. "dcim.device")
        object_id: The numeric ID of the object to delete
        confirm: Must be set to True for a real delete to proceed. Guards against
                 the LLM calling delete with default arguments. Ignored when dry_run=True.
        dry_run: If True, fetch the target object and return what would be deleted
                 without issuing the DELETE.

    Returns:
        On a real call: {"deleted": True, "object_type": ..., "object_id": ...}.
        On dry_run: {"dry_run": True, "object_type": ..., "object_id": ...,
                     "target": <current object>}.
    """
    if object_type not in NETBOX_OBJECT_TYPES:
        valid_types = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
        raise ValueError(f"Invalid object_type. Must be one of:\n{valid_types}")

    _ensure_write_allowed(object_type)

    logger = logging.getLogger(__name__)
    endpoint, fallback = _get_endpoint_info(object_type)

    if dry_run:
        logger.info(f"netbox_delete_object[dry_run]: {object_type} id={object_id}")
        try:
            target = netbox.get(endpoint, id=object_id, fallback_endpoint=fallback)
        except httpx.HTTPStatusError as e:
            raise _httpx_error_to_value_error(e) from e
        return {
            "dry_run": True,
            "object_type": object_type,
            "object_id": object_id,
            "target": target,
        }

    if not confirm:
        raise ValueError(
            "Refusing to delete without explicit confirm=True. Pass confirm=True "
            "to proceed, or dry_run=True to preview the target."
        )

    logger.info(f"netbox_delete_object: {object_type} id={object_id} deleting")
    try:
        deleted = netbox.delete(endpoint, object_id, fallback_endpoint=fallback)
    except httpx.HTTPStatusError as e:
        raise _httpx_error_to_value_error(e) from e

    if not deleted:
        raise RuntimeError(
            f"Delete of {object_type} id={object_id} returned a non-204 success "
            "status; the object may not have been removed. Re-check via netbox_get_object_by_id."
        )

    logger.info(f"netbox_delete_object: {object_type} id={object_id} deleted")
    return {"deleted": True, "object_type": object_type, "object_id": object_id}


@mcp.tool
def netbox_get_changelogs(
    filters: dict,
    limit: Annotated[int, Field(default=5, ge=1, le=100)] = 5,
    offset: Annotated[int, Field(default=0, ge=0)] = 0,
):
    """
    Get object change records (changelogs) from NetBox based on filters.

    Args:
        filters: dict of filters to apply to the API call based on the NetBox API filtering options.
                 Same FILTER RULES as netbox_get_objects apply (no '__in' suffix, no multi-hop
                 traversal); invalid patterns are rejected rather than silently ignored by NetBox.
        limit: Maximum results to return (default 5, max 100). Changelog rows embed full
               pre/post-change object snapshots, so keep this small to bound payload size.
        offset: Skip this many results for pagination (default 0).

    Returns:
        Paginated response dict with the following structure:
            - count: Total number of changelog entries matching the query
                     ALWAYS REFER TO THIS FIELD FOR THE TOTAL NUMBER OF CHANGELOG ENTRIES MATCHING THE QUERY
            - next: URL to next page (or null if no more pages)
                    ALWAYS REFER TO THIS FIELD FOR THE NEXT PAGE OF RESULTS
            - previous: URL to previous page (or null if on first page)
                        ALWAYS REFER TO THIS FIELD FOR THE PREVIOUS PAGE OF RESULTS
            - results: Array of changelog entries for this page
                       ALWAYS REFER TO THIS FIELD FOR THE CHANGELOG ENTRIES ON THIS PAGE

    Filtering options include:
    - user_id: Filter by user ID who made the change
    - user: Filter by username who made the change
    - changed_object_type_id: Filter by numeric ContentType ID (e.g., 21 for dcim.device)
                              Note: This expects a numeric ID, not an object type string
    - changed_object_id: Filter by ID of the changed object
    - object_repr: Filter by object representation (usually contains object name)
    - action: Filter by action type (created, updated, deleted)
    - time_before: Filter for changes made before a given time (ISO 8601 format)
    - time_after: Filter for changes made after a given time (ISO 8601 format)
    - q: Search term to filter by object representation

    Examples:
    To find all changes made to a specific object by ID:
    {"changed_object_id": 123}

    To find changes by object name pattern:
    {"object_repr": "router-01"}

    To find all deletions in the last 24 hours:
    {"action": "delete", "time_after": "2023-01-01T00:00:00Z"}

    Each changelog entry contains:
    - id: The unique identifier of the changelog entry
    - user: The user who made the change
    - user_name: The username of the user who made the change
    - request_id: The unique identifier of the request that made the change
    - action: The type of action performed (created, updated, deleted)
    - changed_object_type: The type of object that was changed
    - changed_object_id: The ID of the object that was changed
    - object_repr: String representation of the changed object
    - object_data: The object's data after the change (null for deletions)
    - object_data_v2: Enhanced data representation
    - prechange_data: The object's data before the change (null for creations)
    - postchange_data: The object's data after the change (null for deletions)
    - time: The timestamp when the change was made
    """
    # Validate filter patterns (consistent with netbox_get_objects)
    validate_filters(filters)

    endpoint = "core/object-changes"

    # Build params with pagination; set after the copy so a limit/offset smuggled
    # into filters cannot override the capped values.
    params = filters.copy()
    params["limit"] = limit
    params["offset"] = offset

    # Make API call
    return netbox.get(endpoint, params=params)


@mcp.tool(
    description="""
    Perform global search across NetBox infrastructure.

    Searches names, descriptions, IP addresses, serial numbers, asset tags,
    and other key fields across multiple object types.

    Args:
        query: Search term (device names, IPs, serial numbers, hostnames, site names)
               Examples: 'switch01', '192.168.1.1', 'NYC-DC1', 'SN123456'
        object_types: Limit search to specific types (optional)
                     Default: ["""
    + "', '".join(DEFAULT_SEARCH_TYPES)
    + """]
                     Examples: ['dcim.device', 'ipam.ipaddress', 'dcim.site']
        fields: Optional list of specific fields to return (reduces response size) IT IS STRONGLY RECOMMENDED TO USE THIS PARAMETER TO MINIMIZE TOKEN USAGE.
                - None or [] = returns all fields (no filtering)
                - ['id', 'name'] = returns only specified fields
                Examples: ['id', 'name', 'status'], ['address', 'dns_name']
                Uses NetBox's native field filtering via ?fields= parameter
        limit: Max results per object type (default 5, max 100)

    Returns:
        Dictionary with object_type keys and list of matching objects. Every
        searched type is present in the result.

        An empty list means no matches ONLY when that type is absent from the
        '_meta'.'errors' map described below. A '_meta' key is added when any type
        failed or was truncated, and is absent entirely when every type succeeded
        in full:
            - _meta.errors: {object_type: reason} for types NetBox could not search.
              Their entry is [] but that [] means "unknown", NOT "no matches".
              DO NOT conclude an object does not exist from a type listed here.
            - _meta.truncated: {object_type: total_count} when more matches exist
              than 'limit' returned. Re-query that type with a higher limit or use
              netbox_get_objects for full pagination.

        Systemic failures (authentication/permission errors, NetBox unreachable or
        returning 5xx) raise instead of returning partial results, so a failed
        search is never reported as "no matches".

    Example:
        # Search for anything matching "switch"
        results = netbox_search_objects('switch')
        # Returns: {
        #   'dcim.device': [{'id': 1, 'name': 'switch-01', ...}],
        #   'dcim.site': [],
        #   ...
        # }

        # A partially degraded search
        results = netbox_search_objects('switch')
        # Returns: {
        #   'dcim.device': [{'id': 1, 'name': 'switch-01', ...}],
        #   'dcim.interface': [],
        #   ...
        #   '_meta': {
        #     'errors': {'dcim.interface': 'NetBox returned HTTP 400'},
        #     'truncated': {'dcim.device': 412},
        #   },
        # }

        # Search for IP address
        results = netbox_search_objects('192.168.1.100')
        # Returns: {
        #   'ipam.ipaddress': [{'id': 42, 'address': '192.168.1.100/24', ...}],
        #   ...
        # }

        # Limit search to specific types with field projection
        results = netbox_search_objects(
            'NYC',
            object_types=['dcim.site', 'dcim.location'],
            fields=['id', 'name', 'status']
        )
    """
)
def netbox_search_objects(
    query: str,
    object_types: list[str] | None = None,
    fields: list[str] | None = None,
    limit: Annotated[int, Field(default=5, ge=1, le=100)] = 5,
) -> dict[str, Any]:
    """
    Perform global search across NetBox infrastructure.

    Returns a dict keyed by object type, each holding the matching rows. A
    reserved SEARCH_META_KEY entry is added when any type errored or was
    truncated; see the tool description for the full contract.
    """
    logger = logging.getLogger(__name__)
    search_types = object_types if object_types is not None else DEFAULT_SEARCH_TYPES

    # Validate all object types exist in mapping
    for obj_type in search_types:
        if obj_type not in NETBOX_OBJECT_TYPES:
            valid_types = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
            raise ValueError(f"Invalid object_type '{obj_type}'. Must be one of:\n{valid_types}")

    results: dict[str, Any] = {obj_type: [] for obj_type in search_types}
    errors: dict[str, str] = {}
    truncated: dict[str, int] = {}

    # Per-type quirks (e.g. an endpoint that does not support the `q` search) are
    # recorded under SEARCH_META_KEY so an empty list never has to carry two
    # meanings. Systemic failures (auth errors, NetBox failing or unreachable) are
    # re-raised, because reporting them per-type would let the caller read "no
    # matches" as proof an object does not exist.
    for obj_type in search_types:
        try:
            endpoint, fallback = _get_endpoint_info(obj_type)
            response = netbox.get(
                endpoint,
                params={
                    "q": query,
                    "limit": limit,
                    "fields": ",".join(fields) if fields else None,
                },
                fallback_endpoint=fallback,
            )
            rows = response.get("results", [])
            results[obj_type] = rows
            # NetBox reports the unpaginated total in `count`; `limit` caps the rows
            # returned. Without this the caller cannot tell 5-of-5 from 5-of-500.
            count = response.get("count")
            if isinstance(count, int) and count > len(rows):
                truncated[obj_type] = count
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            if status in (401, 403):
                # Authentication/permission failure affects every type, not just
                # this one — surface it instead of masking it as an empty result.
                raise
            if status >= 500:
                # NetBox itself is failing (restart, load shedding, upstream 502).
                # Not a per-type quirk, so do not let it look like an absent object.
                raise
            errors[obj_type] = f"NetBox returned HTTP {status}"
            logger.warning(f"Search failed for '{obj_type}': NetBox returned HTTP {status}")
        except httpx.TransportError:
            # Connect/read/timeout/protocol errors all mean NetBox is unreachable or
            # the connection broke — systemic, so never mask it. TransportError is the
            # parent of ConnectError, TimeoutException, ReadError, RemoteProtocolError
            # and ProxyError.
            raise
        except Exception as exc:
            # Resilient to per-type endpoint quirks: record the type and move on.
            errors[obj_type] = str(exc)
            logger.warning(f"Search failed for '{obj_type}': {exc}")

    meta: dict[str, Any] = {}
    if errors:
        meta["errors"] = errors
    if truncated:
        meta["truncated"] = truncated
    if meta:
        # Object types always contain a dot ("app.model"), so this key cannot
        # collide with one. Absent entirely when every type succeeded in full.
        results[SEARCH_META_KEY] = meta

    return results


def _get_endpoint_info(object_type: str) -> tuple[str, str | None]:
    """
    Returns (endpoint, fallback_endpoint) for the given object type.

    The fallback_endpoint is used for NetBox version compatibility when
    an endpoint path has changed between versions.

    Args:
        object_type: The NetBox object type (e.g., "dcim.device")

    Returns:
        Tuple of (endpoint, fallback_endpoint). fallback_endpoint is None
        if no fallback is needed for this object type.
    """
    type_info = NETBOX_OBJECT_TYPES[object_type]
    return type_info["endpoint"], type_info.get("fallback_endpoint")


def discover_plugin_types(client: NetBoxRestClient) -> dict[str, dict[str, str]]:
    """Discover plugin object types from NetBox's object-types API.

    Queries the NetBox instance for installed plugin models that have REST API
    endpoints and returns them in the same format as NETBOX_OBJECT_TYPES.

    Args:
        client: Initialized NetBox REST API client

    Returns:
        Dict mapping type keys (e.g. "netbox_dns.zone") to endpoint info dicts.
        Returns empty dict on any error (graceful degradation).
    """
    logger = logging.getLogger(__name__)
    plugin_types: dict[str, dict[str, str]] = {}

    try:
        # Paginate through all object types
        offset = 0
        limit = 100
        while True:
            response = client.get(
                "core/object-types",
                params={"limit": limit, "offset": offset},
                fallback_endpoint="extras/object-types",  # NetBox < 4.4
            )

            results = response.get("results", [])
            for obj_type in results:
                # Only include plugin models with REST API endpoints
                if not obj_type.get("is_plugin_model", False):
                    continue

                rest_url = obj_type.get("rest_api_endpoint")
                if not rest_url:
                    continue

                app_label = obj_type.get("app_label", "")
                model = obj_type.get("model", "")
                if not app_label or not model:
                    continue

                type_key = f"{app_label}.{model}"

                # Skip if it would collide with a core type
                if type_key in NETBOX_OBJECT_TYPES:
                    logger.debug(f"Skipping plugin type '{type_key}': collides with core type")
                    continue

                # Convert REST URL to endpoint path:
                # "/api/plugins/netbox-dns/zones/" -> "plugins/netbox-dns/zones"
                endpoint = rest_url.strip("/")
                if endpoint.startswith("api/"):
                    endpoint = endpoint[4:]

                # Build a display name from the model name
                display_name = obj_type.get("display", model)

                plugin_types[type_key] = {
                    "name": display_name,
                    "endpoint": endpoint,
                }

            # Check if there are more pages
            if not response.get("next"):
                break
            offset += limit

    except (httpx.HTTPError, ValueError, KeyError) as e:
        logger.warning(f"Plugin discovery failed, continuing with core types only: {e}")
        return {}

    if plugin_types:
        logger.info(
            f"Discovered {len(plugin_types)} plugin object types: "
            + ", ".join(sorted(plugin_types.keys()))
        )
    else:
        logger.info("No plugin object types discovered")

    return plugin_types


async def _update_tool_descriptions() -> None:
    """Update tool descriptions to reflect the current NETBOX_OBJECT_TYPES registry.

    The type list in netbox_get_objects's description is built at import time.
    After plugin discovery adds new types, this refreshes the description so
    LLMs see the full list of available types.
    """
    type_list = "\n".join(f"- {t}" for t in sorted(NETBOX_OBJECT_TYPES.keys()))
    tool = await mcp.get_tool("netbox_get_objects")
    if tool:
        # Replace the type list portion of the description
        desc = tool.description
        marker = "Valid object_type values:"
        idx = desc.find(marker)
        if idx != -1:
            # Keep everything up to and including the marker, then append new list
            prefix = desc[: idx + len(marker)]
            suffix_marker = "See NetBox API documentation"
            suffix_idx = desc.find(suffix_marker)
            suffix = (
                f"\n\n    {suffix_marker}" + desc[suffix_idx + len(suffix_marker) :]
                if suffix_idx != -1
                else ""
            )
            tool.description = f"{prefix}\n\n{type_list}{suffix}"


def _register_write_tools(mcp_instance: FastMCP) -> None:
    """Register write tools on the given FastMCP instance.

    Called from main() only when settings.enable_writes is True, so the
    tools are absent from tools/list by default.
    """
    mcp_instance.tool(netbox_create_object)
    mcp_instance.tool(netbox_update_object)
    mcp_instance.tool(netbox_delete_object)


def _unsafe_runtime_config(settings: Settings) -> str | None:
    """Return an error message if the runtime config is unsafe to start, else None.

    Guards the fail-open cases on the HTTP transport, where the server refuses to
    start rather than emitting only a warning:

    1. Write tools enabled with no bearer token, which would expose an
       unauthenticated create/update/delete endpoint.
    2. Wildcard CORS with no bearer token, which invites any web page to read
       every NetBox object the token can see.

    Args:
        settings: The resolved server settings.

    Returns:
        A human-readable reason to abort startup, or None when the config is safe.
    """
    if settings.transport != "http":
        return None

    if (
        settings.enable_writes
        and settings.mcp_auth_token is None
        and not settings.allow_unauthenticated_writes
    ):
        return (
            "Refusing to start: write tools are enabled on the HTTP transport with no "
            "MCP_AUTH_TOKEN set, which would expose an unauthenticated create/update/"
            "delete endpoint. Set MCP_AUTH_TOKEN (clients then send 'Authorization: "
            "Bearer <token>'), or set ALLOW_UNAUTHENTICATED_WRITES=true to override for "
            "a deployment you have confirmed is unreachable from untrusted networks."
        )

    if "*" in settings.cors_origins and settings.mcp_auth_token is None:
        return (
            "Refusing to start: CORS_ORIGINS includes '*' on the HTTP transport with no "
            "MCP_AUTH_TOKEN set. That combination lets any web page the operator visits "
            "read every NetBox object this token can see. Set MCP_AUTH_TOKEN (clients "
            "then send 'Authorization: Bearer <token>'), or list the specific origins "
            "your client needs instead of '*'."
        )

    return None


def main() -> None:
    """Main entry point for the MCP server."""
    global netbox, write_denied_types

    cli_overlay: dict[str, Any] = parse_cli_args()

    try:
        settings = Settings(**cli_overlay)
    except Exception as e:
        print(f"Configuration error: {e}", file=sys.stderr)  # noqa: T201 - before logging configured
        sys.exit(1)

    configure_logging(settings.log_level)
    logger = logging.getLogger(__name__)

    logger.info("Starting NetBox MCP Server")
    logger.info(f"Effective configuration: {settings.get_effective_config_summary()}")

    # Fail safe before any binding: refuse an unauthenticated write endpoint.
    unsafe = _unsafe_runtime_config(settings)
    if unsafe:
        logger.error(unsafe)
        sys.exit(1)

    # Sync the write deny-list from settings (operators may override the default).
    write_denied_types = set(settings.write_denied_types)

    if not settings.verify_ssl:
        logger.warning(
            "SSL certificate verification is DISABLED. "
            "This is insecure and should only be used for testing."
        )

    if settings.transport == "http" and settings.host in ["0.0.0.0", "::", "[::]"]:  # noqa: S104 - checking, not binding
        logger.warning(
            f"HTTP transport is bound to {settings.host}:{settings.port}, which exposes the "
            "service to all network interfaces (IPv4/IPv6). This is insecure and should only be "
            "used for testing. Ensure this is secured with TLS/reverse proxy if exposed to network."
        )
    elif settings.transport == "http" and settings.host not in [
        "127.0.0.1",
        "localhost",
    ]:
        logger.info(
            f"HTTP transport is bound to {settings.host}:{settings.port}. "
            "Ensure this is secured with TLS/reverse proxy if exposed to network."
        )

    try:
        netbox = NetBoxRestClient(
            url=str(settings.netbox_url),
            token=settings.netbox_token.get_secret_value(),
            verify_ssl=settings.verify_ssl,
            timeout=settings.netbox_timeout,
        )
        logger.debug("NetBox client initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize NetBox client: {e}")
        sys.exit(1)

    plugin_count = 0
    if settings.enable_plugin_discovery:
        plugin_types = discover_plugin_types(netbox)
        plugin_count = len(plugin_types)
        if plugin_types:
            NETBOX_OBJECT_TYPES.update(plugin_types)
            asyncio.run(_update_tool_descriptions())

    if settings.enable_writes:
        _register_write_tools(mcp)
        if settings.transport == "http":
            bind = f"http://{settings.host}:{settings.port}"
        else:
            bind = "stdio"

        # ALLOW_UNAUTHENTICATED_WRITES is documented for localhost-only use, but
        # nothing can verify that from inside the process — and containers must bind
        # 0.0.0.0 to be reachable at all, so the flag and a wildcard bind routinely
        # coexist. Say plainly that only network placement is protecting the endpoint.
        if (
            settings.transport == "http"
            and settings.allow_unauthenticated_writes
            and settings.mcp_auth_token is None
            and settings.host in ["0.0.0.0", "::", "[::]"]  # noqa: S104 - checking, not binding
        ):
            logger.warning(
                f"ALLOW_UNAUTHENTICATED_WRITES is set and the server is bound to "
                f"{settings.host}:{settings.port}, so create/update/delete is reachable "
                "from every network interface with no authentication whatsoever. Nothing "
                "in this server restricts that to localhost — only your network placement "
                "does. Set MCP_AUTH_TOKEN unless you have confirmed the port is "
                "unreachable from untrusted networks."
            )
        denied = ", ".join(sorted(write_denied_types)) or "(none)"
        writable_count = len(NETBOX_OBJECT_TYPES)
        logger.warning(
            f"Write tools ENABLED ({bind}). {writable_count} object type(s) are "
            "writable (core NetBox types plus any discovered plugins). NetBox "
            "API token must have write permissions; all mutations are recorded "
            "in NetBox's changelog. Verify the bind address is not exposed to "
            f"untrusted networks. Write deny-list (security-critical types "
            f"refused): {denied}."
        )
        if plugin_count > 0:
            logger.warning(
                f"Write tools are enabled AND plugin discovery added "
                f"{plugin_count} plugin object type(s) to the writable surface. "
                "Confirm these are intended to be mutable."
            )

        # Advisory preflight: OPTIONS tells us whether the endpoint advertises
        # write methods. NetBox still enforces token permissions on mutation.
        try:
            methods = netbox.verify_write_endpoint_available()
            if methods:
                logger.info(
                    "Representative write endpoint dcim/sites advertises methods: "
                    f"{', '.join(sorted(methods))}"
                )
            else:
                logger.warning(
                    "Could not verify representative write endpoint at startup: "
                    "OPTIONS returned no Allow header. Continuing; NetBox will "
                    "enforce token permissions on mutation."
                )
        except Exception as e:
            logger.warning(
                "Could not verify representative write endpoint at startup "
                f"(continuing; NetBox will enforce token permissions on mutation): {e}"
            )

    try:
        if settings.transport == "stdio":
            logger.info("Starting stdio transport")
            mcp.run(transport="stdio")
        elif settings.transport == "http":
            logger.info(f"Starting HTTP transport on {settings.host}:{settings.port}")
            auth = build_http_auth(settings.mcp_auth_token)
            if auth is not None:
                # FastMCP reads mcp.auth when it builds the HTTP app at run time,
                # so this assignment wires it (the 401 tests verify enforcement).
                mcp.auth = auth
                logger.info("HTTP transport authentication enabled (bearer token required)")
            else:
                logger.warning(
                    "HTTP transport is running WITHOUT authentication. This is not "
                    "safe even when bound to localhost: the MCP HTTP transport does "
                    "not validate the Host or Origin header, so any web page the "
                    "operator visits can reach this endpoint via DNS rebinding and "
                    "read every NetBox object this token can see. Set MCP_AUTH_TOKEN "
                    "(clients then send 'Authorization: Bearer <token>'), or place the "
                    "server behind an authenticating TLS reverse proxy or gateway."
                )
            middleware = [
                Middleware(
                    CORSMiddleware,
                    allow_origins=settings.cors_origins,
                    # DELETE is how the MCP HTTP transport terminates a session; without
                    # it browser clients get a 400 on the preflight.
                    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
                    allow_headers=[
                        "Authorization",
                        "mcp-protocol-version",
                        "mcp-session-id",
                    ],
                    expose_headers=["mcp-session-id"],
                )
            ]
            mcp.run(transport="http", host=settings.host, port=settings.port, middleware=middleware)
    except Exception as e:
        logger.error(f"Failed to start MCP server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
