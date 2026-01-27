"""Detection plugins - Custom rule extensions."""

from sql_injection_protector.layers.detection.plugins.registry import (
    RulePluginRegistry,
    RulePlugin,
    PluginInfo,
    get_registry,
    register_plugin,
)
from sql_injection_protector.layers.detection.plugins.owasp import (
    OWASPSQLiPlugin,
    create_owasp_plugin,
)

__all__ = [
    "RulePluginRegistry",
    "RulePlugin",
    "PluginInfo",
    "get_registry",
    "register_plugin",
    "OWASPSQLiPlugin",
    "create_owasp_plugin",
]
