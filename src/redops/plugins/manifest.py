"""
Plugin Manifest System.

Provides manifest-based plugin configuration and validation.
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


class ManifestError(Exception):
    """Error in plugin manifest."""

    pass


@dataclass
class PluginDependency:
    """Plugin dependency specification."""

    name: str
    version: str = "*"  # Semver constraint
    optional: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "optional": self.optional,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PluginDependency":
        """Create from dictionary."""
        return cls(
            name=data["name"],
            version=data.get("version", "*"),
            optional=data.get("optional", False),
        )

    def matches_version(self, version: str) -> bool:
        """Check if version matches constraint."""
        if self.version == "*":
            return True

        # Simple semver matching
        constraint = self.version

        if constraint.startswith(">="):
            return _compare_versions(version, constraint[2:]) >= 0
        elif constraint.startswith("<="):
            return _compare_versions(version, constraint[2:]) <= 0
        elif constraint.startswith(">"):
            return _compare_versions(version, constraint[1:]) > 0
        elif constraint.startswith("<"):
            return _compare_versions(version, constraint[1:]) < 0
        elif constraint.startswith("^"):
            # Compatible with (major version must match)
            base = constraint[1:]
            return _major_version(version) == _major_version(base)
        elif constraint.startswith("~"):
            # Approximately equal (major.minor must match)
            base = constraint[1:]
            return _major_version(version) == _major_version(base) and _minor_version(
                version
            ) == _minor_version(base)
        else:
            return version == constraint


@dataclass
class PluginRequirement:
    """System requirement for a plugin."""

    name: str
    type: str  # "python", "system", "env"
    version: Optional[str] = None
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "type": self.type,
            "version": self.version,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PluginRequirement":
        """Create from dictionary."""
        return cls(
            name=data["name"],
            type=data["type"],
            version=data.get("version"),
            description=data.get("description", ""),
        )


@dataclass
class PluginManifest:
    """
    Plugin manifest containing metadata and configuration.

    Example manifest.json:
        {
            "name": "port-scanner",
            "version": "1.0.0",
            "description": "Network port scanner plugin",
            "author": "RedOPS Team",
            "license": "MIT",
            "entry_point": "port_scanner:PortScannerPlugin",
            "plugin_type": "scanner",
            "capabilities": ["network_scan"],
            "dependencies": [
                {"name": "nmap", "version": ">=7.0"}
            ],
            "requirements": [
                {"name": "nmap", "type": "system"}
            ]
        }
    """

    # Required fields
    name: str
    version: str
    entry_point: str  # module:ClassName

    # Metadata
    description: str = ""
    author: str = ""
    author_email: str = ""
    license: str = ""
    homepage: str = ""
    repository: str = ""
    documentation: str = ""
    keywords: List[str] = field(default_factory=list)

    # Plugin info
    plugin_type: str = "scanner"  # scanner, enricher, reporter, etc.
    capabilities: List[str] = field(default_factory=list)
    phases: List[str] = field(default_factory=list)

    # Dependencies
    dependencies: List[PluginDependency] = field(default_factory=list)
    requirements: List[PluginRequirement] = field(default_factory=list)
    python_requires: str = ">=3.10"

    # Configuration
    config_schema: Dict[str, Any] = field(default_factory=dict)
    default_config: Dict[str, Any] = field(default_factory=dict)

    # Hooks
    hooks: Dict[str, str] = field(default_factory=dict)  # event -> function

    # Files
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)

    # Metadata
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "entry_point": self.entry_point,
            "description": self.description,
            "author": self.author,
            "author_email": self.author_email,
            "license": self.license,
            "homepage": self.homepage,
            "repository": self.repository,
            "documentation": self.documentation,
            "keywords": self.keywords,
            "plugin_type": self.plugin_type,
            "capabilities": self.capabilities,
            "phases": self.phases,
            "dependencies": [d.to_dict() for d in self.dependencies],
            "requirements": [r.to_dict() for r in self.requirements],
            "python_requires": self.python_requires,
            "config_schema": self.config_schema,
            "default_config": self.default_config,
            "hooks": self.hooks,
            "include": self.include,
            "exclude": self.exclude,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PluginManifest":
        """Create from dictionary."""
        return cls(
            name=data["name"],
            version=data["version"],
            entry_point=data["entry_point"],
            description=data.get("description", ""),
            author=data.get("author", ""),
            author_email=data.get("author_email", ""),
            license=data.get("license", ""),
            homepage=data.get("homepage", ""),
            repository=data.get("repository", ""),
            documentation=data.get("documentation", ""),
            keywords=data.get("keywords", []),
            plugin_type=data.get("plugin_type", "scanner"),
            capabilities=data.get("capabilities", []),
            phases=data.get("phases", []),
            dependencies=[
                PluginDependency.from_dict(d) for d in data.get("dependencies", [])
            ],
            requirements=[
                PluginRequirement.from_dict(r) for r in data.get("requirements", [])
            ],
            python_requires=data.get("python_requires", ">=3.10"),
            config_schema=data.get("config_schema", {}),
            default_config=data.get("default_config", {}),
            hooks=data.get("hooks", {}),
            include=data.get("include", []),
            exclude=data.get("exclude", []),
        )

    @property
    def module_name(self) -> str:
        """Get module name from entry point."""
        return self.entry_point.split(":")[0]

    @property
    def class_name(self) -> str:
        """Get class name from entry point."""
        parts = self.entry_point.split(":")
        return parts[1] if len(parts) > 1 else ""

    def validate(self) -> List[str]:
        """
        Validate the manifest.

        Returns:
            List of validation error messages
        """
        errors = []

        # Required fields
        if not self.name:
            errors.append("Missing required field: name")
        elif not re.match(r"^[a-z][a-z0-9-]*$", self.name):
            errors.append("Invalid name: must be lowercase alphanumeric with hyphens")

        if not self.version:
            errors.append("Missing required field: version")
        elif not _is_valid_semver(self.version):
            errors.append("Invalid version: must be valid semver (e.g., 1.0.0)")

        if not self.entry_point:
            errors.append("Missing required field: entry_point")
        elif ":" not in self.entry_point:
            errors.append("Invalid entry_point: must be module:ClassName")

        # Plugin type
        valid_types = [
            "scanner",
            "enricher",
            "reporter",
            "validator",
            "transformer",
            "hook",
        ]
        if self.plugin_type not in valid_types:
            errors.append(f"Invalid plugin_type: must be one of {valid_types}")

        # Python version constraint
        if not _is_valid_python_constraint(self.python_requires):
            errors.append("Invalid python_requires: must be valid version constraint")

        return errors


def load_manifest(path: Union[str, Path]) -> PluginManifest:
    """
    Load a plugin manifest from file.

    Args:
        path: Path to manifest.json

    Returns:
        PluginManifest object

    Raises:
        ManifestError: If manifest is invalid
    """
    path = Path(path)

    if not path.exists():
        raise ManifestError(f"Manifest not found: {path}")

    try:
        with open(path, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ManifestError(f"Invalid JSON in manifest: {e}")

    manifest = PluginManifest.from_dict(data)

    errors = manifest.validate()
    if errors:
        raise ManifestError(f"Invalid manifest: {'; '.join(errors)}")

    return manifest


def save_manifest(manifest: PluginManifest, path: Union[str, Path]) -> None:
    """
    Save a plugin manifest to file.

    Args:
        manifest: Manifest to save
        path: Output path

    Raises:
        ManifestError: If manifest is invalid
    """
    errors = manifest.validate()
    if errors:
        raise ManifestError(f"Invalid manifest: {'; '.join(errors)}")

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w") as f:
        json.dump(manifest.to_dict(), f, indent=2)


def validate_manifest(data: Dict[str, Any]) -> List[str]:
    """
    Validate manifest data without creating object.

    Args:
        data: Manifest data dictionary

    Returns:
        List of validation errors
    """
    try:
        manifest = PluginManifest.from_dict(data)
        return manifest.validate()
    except (KeyError, TypeError) as e:
        return [f"Invalid manifest structure: {e}"]


def _is_valid_semver(version: str) -> bool:
    """Check if version is valid semver."""
    pattern = r"^(\d+)\.(\d+)\.(\d+)(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$"
    return bool(re.match(pattern, version))


def _compare_versions(v1: str, v2: str) -> int:
    """Compare two semver versions. Returns -1, 0, or 1."""

    def parse(v):
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)", v)
        if match:
            return tuple(int(x) for x in match.groups())
        return (0, 0, 0)

    p1 = parse(v1)
    p2 = parse(v2)

    if p1 < p2:
        return -1
    elif p1 > p2:
        return 1
    return 0


def _major_version(version: str) -> int:
    """Extract major version number."""
    match = re.match(r"^(\d+)", version)
    return int(match.group(1)) if match else 0


def _minor_version(version: str) -> int:
    """Extract minor version number."""
    match = re.match(r"^\d+\.(\d+)", version)
    return int(match.group(1)) if match else 0


def _is_valid_python_constraint(constraint: str) -> bool:
    """Check if Python version constraint is valid."""
    pattern = r"^[>=<~^]*\d+(\.\d+)*$"
    return bool(re.match(pattern, constraint))
