"""Tests that every setting is documented, and that no doc reproduces a deny-list.

Two drift classes have already bitten this repo:

1. A setting exists in config.py but no operator-facing file mentions it, so
   nobody discovers it (ENABLE_PLUGIN_DISCOVERY was absent from .env.example).
2. A doc reproduces DEFAULT_WRITE_DENIED_TYPES as a copy-pasteable value and then
   goes stale. That is worse than missing docs: an operator pasting a 4-entry list
   over the current 8-entry default silently REMOVES write protection.

These tests fail on the drift rather than on a snapshot, so they do not need
updating when a setting or a deny-list entry is added.
"""

import re
from pathlib import Path

import pytest

from netbox_mcp_server.config import DEFAULT_WRITE_DENIED_TYPES, Settings

REPO_ROOT = Path(__file__).resolve().parent.parent
ENV_EXAMPLE = REPO_ROOT / ".env.example"
README = REPO_ROOT / "README.md"

# Documented under its own name in README's configuration table but intentionally
# not offered as an .env.example line, because setting it wrong is a downgrade.
ENV_EXAMPLE_EXEMPT: set[str] = set()


def _setting_env_names() -> list[str]:
    """Env var name for each Settings field (env_prefix is empty, so name.upper())."""
    return [name.upper() for name in Settings.model_fields]


@pytest.mark.parametrize("env_name", _setting_env_names())
def test_setting_appears_in_env_example(env_name):
    """Every setting is discoverable from .env.example."""
    if env_name in ENV_EXAMPLE_EXEMPT:
        pytest.skip(f"{env_name} is deliberately not offered as an .env.example line")
    assert env_name in ENV_EXAMPLE.read_text(), (
        f"{env_name} is a Settings field but is absent from .env.example. "
        "An operator treating that file as canonical will never learn it exists."
    )


@pytest.mark.parametrize("env_name", _setting_env_names())
def test_setting_appears_in_readme(env_name):
    """Every setting is documented in README.md."""
    assert env_name in README.read_text(), (
        f"{env_name} is a Settings field but is absent from README.md. "
        "A user-facing setting is not documented until it is in the README."
    )


def test_deny_list_default_is_not_reproduced_as_a_settable_value():
    """No doc may offer a WRITE_DENIED_TYPES= value.

    A hardcoded list drifts from DEFAULT_WRITE_DENIED_TYPES and, being
    copy-pasteable, turns that drift into removed protection. Docs must point at
    config.py instead. A bare 'WRITE_DENIED_TYPES=' placeholder is fine.
    """
    settable = re.compile(r"^\s*#?\s*WRITE_DENIED_TYPES\s*=\s*\S")
    for path in (ENV_EXAMPLE, README):
        offenders = [line for line in path.read_text().splitlines() if settable.match(line)]
        assert not offenders, (
            f"{path.name} offers a concrete WRITE_DENIED_TYPES value: {offenders}. "
            "This goes stale and silently removes protection when pasted. "
            "Point at DEFAULT_WRITE_DENIED_TYPES in config.py instead."
        )


@pytest.mark.parametrize("denied_type", DEFAULT_WRITE_DENIED_TYPES)
def test_every_denied_type_is_described_in_readme(denied_type):
    """The README's write-safeguards note covers each denied type.

    Prose is fine here — what must not exist is a settable value (see above).
    """
    assert denied_type in README.read_text(), (
        f"{denied_type} is denied by default but is not mentioned in README.md, "
        "so operators cannot tell what the safeguard actually covers."
    )
