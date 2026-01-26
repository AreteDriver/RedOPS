"""
RedOPS Plugin System.

Provides extensible scanner plugins, manifest-based configuration,
and plugin repository management.
"""

from redops.plugins.scanner import (
    ScannerPlugin,
    ScannerResult,
    Finding,
    Severity,
    ScanPhase,
    ScannerConfig,
    ScannerCapability,
)
from redops.plugins.manifest import (
    PluginManifest,
    PluginDependency,
    PluginRequirement,
    ManifestError,
    load_manifest,
    save_manifest,
    validate_manifest,
)
from redops.plugins.repository import (
    PluginRepository,
    PluginSource,
    PluginInfo,
    PluginVersion,
    install_plugin,
    uninstall_plugin,
    list_installed_plugins,
    search_plugins,
)

__all__ = [
    # Scanner plugins
    "ScannerPlugin",
    "ScannerResult",
    "Finding",
    "Severity",
    "ScanPhase",
    "ScannerConfig",
    "ScannerCapability",
    # Manifest
    "PluginManifest",
    "PluginDependency",
    "PluginRequirement",
    "ManifestError",
    "load_manifest",
    "save_manifest",
    "validate_manifest",
    # Repository
    "PluginRepository",
    "PluginSource",
    "PluginInfo",
    "PluginVersion",
    "install_plugin",
    "uninstall_plugin",
    "list_installed_plugins",
    "search_plugins",
]
