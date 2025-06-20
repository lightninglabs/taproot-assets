"""A plugin that checks for forbidden foreign key types in SQL

This uses the rules API supported from 0.4.0 onwards.
"""

from typing import Any

from sqlfluff.core.config import load_config_resource
from sqlfluff.core.plugin import hookimpl
from sqlfluff.core.rules import BaseRule, ConfigInfo


@hookimpl
def get_rules() -> list[type[BaseRule]]:
    """Get plugin rules.
    """
    # i.e. we DO recommend importing here:
    from .rules import Rule_LL01  # noqa: F811

    return [Rule_LL01]


@hookimpl
def load_default_config() -> dict[str, Any]:
    """Loads the default configuration for the plugin."""
    return {}


@hookimpl
def get_configs_info() -> dict[str, dict[str, ConfigInfo]]:
    """Get rule config validations and descriptions."""
    return {}