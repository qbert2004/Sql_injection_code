"""Plugin registry for custom detection rules."""

import importlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional, Protocol, runtime_checkable

from sql_injection_protector.layers.detection.signature import SignatureRule

logger = logging.getLogger(__name__)


@runtime_checkable
class RulePlugin(Protocol):
    """Protocol for rule plugins."""

    @property
    def name(self) -> str:
        """Plugin name."""
        ...

    @property
    def version(self) -> str:
        """Plugin version."""
        ...

    def get_rules(self) -> list[SignatureRule]:
        """Get signature rules from this plugin."""
        ...


@dataclass
class PluginInfo:
    """Information about a registered plugin."""

    name: str
    version: str
    enabled: bool
    rule_count: int
    source: str  # 'builtin', 'file', 'module'
    metadata: dict[str, Any] = field(default_factory=dict)


class RulePluginRegistry:
    """
    Registry for managing rule plugins.

    Supports:
    - Built-in plugins
    - File-based plugins (YAML)
    - Module-based plugins (Python)
    """

    def __init__(self):
        """Initialize the plugin registry."""
        self._plugins: dict[str, RulePlugin] = {}
        self._plugin_info: dict[str, PluginInfo] = {}
        self._rules_cache: dict[str, list[SignatureRule]] = {}
        self._enabled: dict[str, bool] = {}

    def register(
        self,
        plugin: RulePlugin,
        source: str = "custom",
        enabled: bool = True,
    ) -> bool:
        """
        Register a plugin.

        Args:
            plugin: Plugin instance
            source: Source identifier
            enabled: Whether plugin is enabled

        Returns:
            True if registration successful
        """
        try:
            name = plugin.name
            rules = plugin.get_rules()

            self._plugins[name] = plugin
            self._enabled[name] = enabled
            self._rules_cache[name] = rules

            self._plugin_info[name] = PluginInfo(
                name=name,
                version=plugin.version,
                enabled=enabled,
                rule_count=len(rules),
                source=source,
            )

            logger.info(f"Registered plugin '{name}' with {len(rules)} rules")
            return True

        except Exception as e:
            logger.error(f"Failed to register plugin: {e}")
            return False

    def unregister(self, name: str) -> bool:
        """
        Unregister a plugin.

        Args:
            name: Plugin name

        Returns:
            True if unregistration successful
        """
        if name in self._plugins:
            del self._plugins[name]
            del self._plugin_info[name]
            del self._rules_cache[name]
            del self._enabled[name]
            logger.info(f"Unregistered plugin '{name}'")
            return True
        return False

    def enable(self, name: str) -> bool:
        """Enable a plugin."""
        if name in self._plugins:
            self._enabled[name] = True
            self._plugin_info[name].enabled = True
            return True
        return False

    def disable(self, name: str) -> bool:
        """Disable a plugin."""
        if name in self._plugins:
            self._enabled[name] = False
            self._plugin_info[name].enabled = False
            return True
        return False

    def is_enabled(self, name: str) -> bool:
        """Check if a plugin is enabled."""
        return self._enabled.get(name, False)

    def get_plugin(self, name: str) -> Optional[RulePlugin]:
        """Get a plugin by name."""
        return self._plugins.get(name)

    def get_plugin_info(self, name: str) -> Optional[PluginInfo]:
        """Get plugin information."""
        return self._plugin_info.get(name)

    def list_plugins(self) -> list[PluginInfo]:
        """List all registered plugins."""
        return list(self._plugin_info.values())

    def get_all_rules(self, enabled_only: bool = True) -> list[SignatureRule]:
        """
        Get all rules from all plugins.

        Args:
            enabled_only: Only include rules from enabled plugins

        Returns:
            Combined list of rules
        """
        rules = []
        for name, plugin_rules in self._rules_cache.items():
            if enabled_only and not self._enabled.get(name, False):
                continue
            rules.extend(plugin_rules)
        return rules

    def get_rules_by_plugin(self, name: str) -> list[SignatureRule]:
        """Get rules from a specific plugin."""
        return self._rules_cache.get(name, [])

    def load_from_yaml(self, path: str) -> bool:
        """
        Load rules from a YAML file.

        Expected format:
        ```yaml
        name: my-rules
        version: 1.0.0
        rules:
          - id: CUSTOM-001
            name: my_rule
            pattern: "regex pattern"
            severity: 0.8
            category: custom
            description: My custom rule
        ```
        """
        import re

        import yaml

        try:
            with open(path) as f:
                data = yaml.safe_load(f)

            name = data.get("name", Path(path).stem)
            version = data.get("version", "1.0.0")

            rules = []
            for rule_data in data.get("rules", []):
                rule = SignatureRule(
                    id=rule_data["id"],
                    name=rule_data["name"],
                    pattern=re.compile(rule_data["pattern"], re.IGNORECASE),
                    severity=float(rule_data.get("severity", 0.5)),
                    category=rule_data.get("category", "custom"),
                    description=rule_data.get("description", ""),
                    enabled=rule_data.get("enabled", True),
                )
                rules.append(rule)

            # Create a simple plugin wrapper
            plugin = YAMLRulePlugin(name, version, rules)
            return self.register(plugin, source="file")

        except Exception as e:
            logger.error(f"Failed to load YAML rules from {path}: {e}")
            return False

    def load_from_module(self, module_path: str) -> bool:
        """
        Load a plugin from a Python module.

        The module should have a class that implements RulePlugin.
        """
        try:
            module = importlib.import_module(module_path)

            # Find plugin class
            plugin_class = None
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (
                    isinstance(attr, type)
                    and attr_name.endswith("Plugin")
                    and isinstance(attr(), RulePlugin)
                ):
                    plugin_class = attr
                    break

            if plugin_class is None:
                logger.error(f"No plugin class found in module {module_path}")
                return False

            plugin = plugin_class()
            return self.register(plugin, source="module")

        except Exception as e:
            logger.error(f"Failed to load plugin from {module_path}: {e}")
            return False

    def load_from_directory(self, directory: str) -> int:
        """
        Load all YAML plugins from a directory.

        Args:
            directory: Path to directory containing YAML files

        Returns:
            Number of plugins loaded
        """
        loaded = 0
        dir_path = Path(directory)

        if not dir_path.exists():
            return 0

        for yaml_file in dir_path.glob("*.yaml"):
            if self.load_from_yaml(str(yaml_file)):
                loaded += 1

        for yml_file in dir_path.glob("*.yml"):
            if self.load_from_yaml(str(yml_file)):
                loaded += 1

        return loaded


class YAMLRulePlugin:
    """Simple plugin wrapper for YAML-loaded rules."""

    def __init__(self, name: str, version: str, rules: list[SignatureRule]):
        self._name = name
        self._version = version
        self._rules = rules

    @property
    def name(self) -> str:
        return self._name

    @property
    def version(self) -> str:
        return self._version

    def get_rules(self) -> list[SignatureRule]:
        return self._rules


# Global registry instance
_global_registry: Optional[RulePluginRegistry] = None


def get_registry() -> RulePluginRegistry:
    """Get the global plugin registry."""
    global _global_registry
    if _global_registry is None:
        _global_registry = RulePluginRegistry()
    return _global_registry


def register_plugin(plugin: RulePlugin, **kwargs) -> bool:
    """Register a plugin in the global registry."""
    return get_registry().register(plugin, **kwargs)
