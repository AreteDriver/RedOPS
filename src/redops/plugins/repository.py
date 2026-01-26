"""
Plugin Repository.

Provides plugin discovery, installation, and management.
"""

import hashlib
import importlib
import importlib.util
import json
import shutil
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urlparse

from redops.plugins.manifest import PluginManifest, load_manifest, ManifestError


class PluginSource(Enum):
    """Plugin installation source."""

    LOCAL = "local"
    DIRECTORY = "directory"
    ZIP = "zip"
    GIT = "git"
    PYPI = "pypi"
    URL = "url"


@dataclass
class PluginVersion:
    """Version information for a plugin."""

    version: str
    released_at: Optional[datetime] = None
    download_url: Optional[str] = None
    checksum: Optional[str] = None
    changelog: str = ""


@dataclass
class PluginInfo:
    """Information about a plugin."""

    name: str
    version: str
    description: str = ""
    author: str = ""
    source: PluginSource = PluginSource.LOCAL
    source_url: str = ""
    installed: bool = False
    installed_at: Optional[datetime] = None
    path: Optional[Path] = None
    manifest: Optional[PluginManifest] = None
    available_versions: List[PluginVersion] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "source": self.source.value,
            "source_url": self.source_url,
            "installed": self.installed,
            "installed_at": self.installed_at.isoformat() if self.installed_at else None,
            "path": str(self.path) if self.path else None,
            "available_versions": [
                {"version": v.version, "released_at": v.released_at.isoformat() if v.released_at else None}
                for v in self.available_versions
            ],
            "metadata": self.metadata,
        }


class PluginRepository:
    """
    Plugin repository for managing plugins.

    Handles plugin discovery, installation, updates, and removal.

    Example:
        repo = PluginRepository("/path/to/plugins")

        # Install from directory
        repo.install("/path/to/plugin")

        # Install from ZIP
        repo.install_zip("/path/to/plugin.zip")

        # List installed plugins
        for plugin in repo.list_installed():
            print(f"{plugin.name} v{plugin.version}")

        # Load plugin
        plugin_class = repo.load("my-plugin")
    """

    def __init__(
        self,
        plugins_dir: Optional[Path] = None,
        registry_url: Optional[str] = None,
    ):
        """
        Initialize the repository.

        Args:
            plugins_dir: Directory to store installed plugins
            registry_url: URL of plugin registry for remote discovery
        """
        self._plugins_dir = Path(plugins_dir) if plugins_dir else Path.home() / ".redops" / "plugins"
        self._registry_url = registry_url
        self._installed: Dict[str, PluginInfo] = {}
        self._loaded: Dict[str, Any] = {}
        self._hooks: Dict[str, List[Callable]] = {
            "pre_install": [],
            "post_install": [],
            "pre_uninstall": [],
            "post_uninstall": [],
        }

        # Ensure plugins directory exists
        self._plugins_dir.mkdir(parents=True, exist_ok=True)

        # Load installed plugins index
        self._load_index()

    def _load_index(self) -> None:
        """Load installed plugins index."""
        index_path = self._plugins_dir / "index.json"
        if index_path.exists():
            try:
                with open(index_path, "r") as f:
                    data = json.load(f)

                for name, info in data.get("plugins", {}).items():
                    self._installed[name] = PluginInfo(
                        name=info["name"],
                        version=info["version"],
                        description=info.get("description", ""),
                        author=info.get("author", ""),
                        source=PluginSource(info.get("source", "local")),
                        source_url=info.get("source_url", ""),
                        installed=True,
                        installed_at=datetime.fromisoformat(info["installed_at"]) if info.get("installed_at") else None,
                        path=Path(info["path"]) if info.get("path") else None,
                    )
            except (json.JSONDecodeError, KeyError):
                pass

    def _save_index(self) -> None:
        """Save installed plugins index."""
        index_path = self._plugins_dir / "index.json"

        data = {
            "version": 1,
            "updated_at": datetime.now().isoformat(),
            "plugins": {
                name: {
                    "name": info.name,
                    "version": info.version,
                    "description": info.description,
                    "author": info.author,
                    "source": info.source.value,
                    "source_url": info.source_url,
                    "installed_at": info.installed_at.isoformat() if info.installed_at else None,
                    "path": str(info.path) if info.path else None,
                }
                for name, info in self._installed.items()
            },
        }

        with open(index_path, "w") as f:
            json.dump(data, f, indent=2)

    def install(
        self,
        source: str,
        force: bool = False,
        config: Optional[Dict[str, Any]] = None,
    ) -> PluginInfo:
        """
        Install a plugin from various sources.

        Args:
            source: Path, URL, or package name
            force: Overwrite existing installation
            config: Plugin configuration

        Returns:
            PluginInfo for installed plugin

        Raises:
            ManifestError: If plugin is invalid
            ValueError: If source is invalid
        """
        # Detect source type
        source_type = self._detect_source_type(source)

        if source_type == PluginSource.DIRECTORY:
            return self._install_from_directory(Path(source), force)
        elif source_type == PluginSource.ZIP:
            return self._install_from_zip(Path(source), force)
        elif source_type == PluginSource.GIT:
            return self._install_from_git(source, force)
        elif source_type == PluginSource.URL:
            return self._install_from_url(source, force)
        else:
            raise ValueError(f"Unknown source type: {source}")

    def _detect_source_type(self, source: str) -> PluginSource:
        """Detect the type of plugin source."""
        path = Path(source)

        if path.is_dir():
            return PluginSource.DIRECTORY
        elif path.is_file() and path.suffix == ".zip":
            return PluginSource.ZIP
        elif source.startswith("git://") or source.endswith(".git"):
            return PluginSource.GIT
        elif source.startswith(("http://", "https://")):
            return PluginSource.URL
        else:
            return PluginSource.LOCAL

    def _install_from_directory(
        self,
        source_dir: Path,
        force: bool = False,
    ) -> PluginInfo:
        """Install plugin from directory."""
        manifest_path = source_dir / "manifest.json"
        if not manifest_path.exists():
            raise ManifestError(f"No manifest.json found in {source_dir}")

        manifest = load_manifest(manifest_path)

        # Check if already installed
        if manifest.name in self._installed and not force:
            raise ValueError(f"Plugin {manifest.name} already installed")

        # Run pre-install hooks
        self._run_hooks("pre_install", manifest)

        # Copy to plugins directory
        dest_dir = self._plugins_dir / manifest.name
        if dest_dir.exists():
            shutil.rmtree(dest_dir)

        shutil.copytree(source_dir, dest_dir)

        # Create plugin info
        info = PluginInfo(
            name=manifest.name,
            version=manifest.version,
            description=manifest.description,
            author=manifest.author,
            source=PluginSource.DIRECTORY,
            source_url=str(source_dir),
            installed=True,
            installed_at=datetime.now(),
            path=dest_dir,
            manifest=manifest,
        )

        self._installed[manifest.name] = info
        self._save_index()

        # Run post-install hooks
        self._run_hooks("post_install", manifest, info)

        return info

    def _install_from_zip(
        self,
        zip_path: Path,
        force: bool = False,
    ) -> PluginInfo:
        """Install plugin from ZIP file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Extract ZIP
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(temp_path)

            # Find manifest (might be in root or subdirectory)
            manifest_path = temp_path / "manifest.json"
            if not manifest_path.exists():
                # Check subdirectories
                for subdir in temp_path.iterdir():
                    if subdir.is_dir():
                        sub_manifest = subdir / "manifest.json"
                        if sub_manifest.exists():
                            temp_path = subdir
                            break
                else:
                    raise ManifestError("No manifest.json found in ZIP")

            return self._install_from_directory(temp_path, force)

    def _install_from_git(
        self,
        git_url: str,
        force: bool = False,
    ) -> PluginInfo:
        """Install plugin from Git repository."""
        import subprocess

        with tempfile.TemporaryDirectory() as temp_dir:
            # Clone repository
            result = subprocess.run(
                ["git", "clone", "--depth", "1", git_url, temp_dir],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise ValueError(f"Git clone failed: {result.stderr}")

            return self._install_from_directory(Path(temp_dir), force)

    def _install_from_url(
        self,
        url: str,
        force: bool = False,
    ) -> PluginInfo:
        """Install plugin from URL."""
        import urllib.request

        with tempfile.TemporaryDirectory() as temp_dir:
            # Download file
            parsed = urlparse(url)
            filename = Path(parsed.path).name or "plugin.zip"
            download_path = Path(temp_dir) / filename

            urllib.request.urlretrieve(url, download_path)

            # Install based on file type
            if download_path.suffix == ".zip":
                return self._install_from_zip(download_path, force)
            else:
                raise ValueError(f"Unsupported file type: {download_path.suffix}")

    def uninstall(self, name: str) -> bool:
        """
        Uninstall a plugin.

        Args:
            name: Plugin name

        Returns:
            True if uninstalled
        """
        if name not in self._installed:
            return False

        info = self._installed[name]

        # Run pre-uninstall hooks
        self._run_hooks("pre_uninstall", name, info)

        # Remove plugin directory
        if info.path and info.path.exists():
            shutil.rmtree(info.path)

        # Remove from loaded
        if name in self._loaded:
            del self._loaded[name]

        # Remove from installed
        del self._installed[name]
        self._save_index()

        # Run post-uninstall hooks
        self._run_hooks("post_uninstall", name)

        return True

    def upgrade(
        self,
        name: str,
        version: Optional[str] = None,
    ) -> PluginInfo:
        """
        Upgrade a plugin to a newer version.

        Args:
            name: Plugin name
            version: Target version (latest if None)

        Returns:
            Updated PluginInfo
        """
        if name not in self._installed:
            raise ValueError(f"Plugin {name} not installed")

        info = self._installed[name]

        if not info.source_url:
            raise ValueError(f"Plugin {name} has no source URL")

        # Re-install from source
        return self.install(info.source_url, force=True)

    def load(self, name: str) -> Any:
        """
        Load a plugin and return its class.

        Args:
            name: Plugin name

        Returns:
            Plugin class

        Raises:
            ValueError: If plugin not found
            ImportError: If plugin fails to load
        """
        if name in self._loaded:
            return self._loaded[name]

        if name not in self._installed:
            raise ValueError(f"Plugin {name} not installed")

        info = self._installed[name]
        if not info.path:
            raise ValueError(f"Plugin {name} has no path")

        # Load manifest if not cached
        if not info.manifest:
            manifest_path = info.path / "manifest.json"
            info.manifest = load_manifest(manifest_path)

        manifest = info.manifest

        # Add plugin directory to path
        plugin_dir = str(info.path)
        if plugin_dir not in sys.path:
            sys.path.insert(0, plugin_dir)

        # Import module
        try:
            module = importlib.import_module(manifest.module_name)

            # Get class
            plugin_class = getattr(module, manifest.class_name)

            self._loaded[name] = plugin_class
            return plugin_class

        except ImportError as e:
            raise ImportError(f"Failed to load plugin {name}: {e}")
        except AttributeError as e:
            raise ImportError(f"Plugin class not found: {e}")

    def list_installed(self) -> List[PluginInfo]:
        """Get list of installed plugins."""
        return list(self._installed.values())

    def get_info(self, name: str) -> Optional[PluginInfo]:
        """Get information about a plugin."""
        return self._installed.get(name)

    def is_installed(self, name: str) -> bool:
        """Check if a plugin is installed."""
        return name in self._installed

    def discover_local(self) -> List[PluginInfo]:
        """
        Discover plugins in the plugins directory.

        Returns:
            List of discovered plugins
        """
        discovered = []

        for plugin_dir in self._plugins_dir.iterdir():
            if not plugin_dir.is_dir():
                continue

            manifest_path = plugin_dir / "manifest.json"
            if not manifest_path.exists():
                continue

            try:
                manifest = load_manifest(manifest_path)
                info = PluginInfo(
                    name=manifest.name,
                    version=manifest.version,
                    description=manifest.description,
                    author=manifest.author,
                    source=PluginSource.LOCAL,
                    path=plugin_dir,
                    manifest=manifest,
                )

                # Check if in installed index
                if manifest.name in self._installed:
                    info.installed = True
                    info.installed_at = self._installed[manifest.name].installed_at

                discovered.append(info)

            except ManifestError:
                continue

        return discovered

    def add_hook(self, event: str, callback: Callable) -> None:
        """Add a hook callback."""
        if event in self._hooks:
            self._hooks[event].append(callback)

    def _run_hooks(self, event: str, *args, **kwargs) -> None:
        """Run hook callbacks."""
        for callback in self._hooks.get(event, []):
            try:
                callback(*args, **kwargs)
            except Exception:
                pass

    @property
    def plugins_dir(self) -> Path:
        """Get plugins directory."""
        return self._plugins_dir


# Module-level convenience functions

_default_repository: Optional[PluginRepository] = None


def get_repository() -> PluginRepository:
    """Get the default plugin repository."""
    global _default_repository
    if _default_repository is None:
        _default_repository = PluginRepository()
    return _default_repository


def install_plugin(source: str, force: bool = False) -> PluginInfo:
    """Install a plugin using the default repository."""
    return get_repository().install(source, force)


def uninstall_plugin(name: str) -> bool:
    """Uninstall a plugin using the default repository."""
    return get_repository().uninstall(name)


def list_installed_plugins() -> List[PluginInfo]:
    """List installed plugins using the default repository."""
    return get_repository().list_installed()


def search_plugins(query: str) -> List[PluginInfo]:
    """
    Search for plugins.

    Currently only searches installed plugins.
    Could be extended to search remote registries.
    """
    repo = get_repository()
    results = []

    query_lower = query.lower()
    for info in repo.list_installed():
        if (
            query_lower in info.name.lower() or
            query_lower in info.description.lower()
        ):
            results.append(info)

    return results
