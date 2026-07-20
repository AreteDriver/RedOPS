"""
Secrets Manager - Secure credential storage and management.

Provides encryption, key rotation, and secure access to sensitive data.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable
import logging

logger = logging.getLogger(__name__)


class SecretType(Enum):
    """Types of secrets."""

    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    CERTIFICATE = "certificate"
    PRIVATE_KEY = "private_key"
    CONNECTION_STRING = "connection_string"
    OAUTH_TOKEN = "oauth_token"
    SSH_KEY = "ssh_key"
    GENERIC = "generic"


class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms."""

    AES_256_GCM = "aes-256-gcm"
    AES_256_CBC = "aes-256-cbc"
    CHACHA20_POLY1305 = "chacha20-poly1305"
    FERNET = "fernet"  # Default, uses cryptography library


@dataclass
class SecretMetadata:
    """Metadata about a secret."""

    name: str
    secret_type: SecretType = SecretType.GENERIC
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    expires_at: datetime | None = None
    version: int = 1
    tags: dict[str, str] = field(default_factory=dict)
    description: str = ""
    rotation_policy: str | None = None
    last_rotated: datetime | None = None
    access_count: int = 0
    last_accessed: datetime | None = None

    def is_expired(self) -> bool:
        """Check if secret has expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "secret_type": self.secret_type.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "version": self.version,
            "tags": self.tags,
            "description": self.description,
            "rotation_policy": self.rotation_policy,
            "last_rotated": self.last_rotated.isoformat()
            if self.last_rotated
            else None,
            "access_count": self.access_count,
            "last_accessed": self.last_accessed.isoformat()
            if self.last_accessed
            else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecretMetadata":
        """Create from dictionary."""
        return cls(
            name=data["name"],
            secret_type=SecretType(data.get("secret_type", "generic")),
            created_at=datetime.fromisoformat(data["created_at"])
            if data.get("created_at")
            else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"])
            if data.get("updated_at")
            else datetime.now(),
            expires_at=datetime.fromisoformat(data["expires_at"])
            if data.get("expires_at")
            else None,
            version=data.get("version", 1),
            tags=data.get("tags", {}),
            description=data.get("description", ""),
            rotation_policy=data.get("rotation_policy"),
            last_rotated=datetime.fromisoformat(data["last_rotated"])
            if data.get("last_rotated")
            else None,
            access_count=data.get("access_count", 0),
            last_accessed=datetime.fromisoformat(data["last_accessed"])
            if data.get("last_accessed")
            else None,
        )


@dataclass
class Secret:
    """A secret with its value and metadata."""

    value: str
    metadata: SecretMetadata
    encrypted: bool = False

    def __repr__(self) -> str:
        """Hide value in repr."""
        return f"Secret(name={self.metadata.name!r}, type={self.metadata.secret_type.value}, version={self.metadata.version})"

    def __str__(self) -> str:
        """Hide value in str."""
        return f"Secret({self.metadata.name})"

    def mask(self, show_chars: int = 4) -> str:
        """Return masked version of secret value."""
        if len(self.value) <= show_chars:
            return "*" * len(self.value)
        return self.value[:show_chars] + "*" * (len(self.value) - show_chars)


class EncryptionProvider(ABC):
    """Abstract base class for encryption providers."""

    @abstractmethod
    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext and return ciphertext."""
        pass

    @abstractmethod
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext and return plaintext."""
        pass

    @abstractmethod
    def rotate_key(self) -> None:
        """Rotate the encryption key."""
        pass


class FernetEncryption(EncryptionProvider):
    """Fernet symmetric encryption (AES-128-CBC with HMAC)."""

    def __init__(self, key: bytes | None = None):
        """
        Initialize Fernet encryption.

        Args:
            key: 32-byte URL-safe base64-encoded key, or None to generate
        """
        try:
            from cryptography.fernet import Fernet

            self._fernet_class = Fernet
        except ImportError:
            raise ImportError("cryptography package required: pip install cryptography")

        if key is None:
            key = Fernet.generate_key()

        self._key = key
        self._fernet = Fernet(key)
        self._previous_keys: list[bytes] = []

    @property
    def key(self) -> bytes:
        """Get the current encryption key."""
        return self._key

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext using Fernet."""
        token = self._fernet.encrypt(plaintext.encode())
        return base64.urlsafe_b64encode(token).decode()

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext using Fernet."""
        from cryptography.fernet import InvalidToken

        try:
            token = base64.urlsafe_b64decode(ciphertext.encode())
        except (ValueError, TypeError) as exc:
            raise ValueError("Unable to decrypt: invalid ciphertext encoding") from exc

        # Try current key first
        try:
            return self._fernet.decrypt(token).decode()
        except InvalidToken:
            pass

        # Try previous keys for rotation
        for prev_key in self._previous_keys:
            try:
                prev_fernet = self._fernet_class(prev_key)
                return prev_fernet.decrypt(token).decode()
            except InvalidToken:
                continue

        raise ValueError("Unable to decrypt: invalid key or corrupted data")

    def rotate_key(self) -> None:
        """Generate a new key and keep the old one for decryption."""
        self._previous_keys.append(self._key)
        self._key = self._fernet_class.generate_key()
        self._fernet = self._fernet_class(self._key)


class SecretBackend(ABC):
    """Abstract base class for secret storage backends."""

    @abstractmethod
    def get(self, name: str) -> Secret | None:
        """Get a secret by name."""
        pass

    @abstractmethod
    def set(self, secret: Secret) -> None:
        """Store a secret."""
        pass

    @abstractmethod
    def delete(self, name: str) -> bool:
        """Delete a secret by name."""
        pass

    @abstractmethod
    def list(self) -> list[str]:
        """List all secret names."""
        pass

    @abstractmethod
    def exists(self, name: str) -> bool:
        """Check if a secret exists."""
        pass


class MemoryBackend(SecretBackend):
    """In-memory secret storage (for testing/development)."""

    def __init__(self):
        """Initialize memory backend."""
        self._secrets: dict[str, Secret] = {}
        self._lock = threading.RLock()

    def get(self, name: str) -> Secret | None:
        """Get a secret by name."""
        with self._lock:
            return self._secrets.get(name)

    def set(self, secret: Secret) -> None:
        """Store a secret."""
        with self._lock:
            self._secrets[secret.metadata.name] = secret

    def delete(self, name: str) -> bool:
        """Delete a secret by name."""
        with self._lock:
            if name in self._secrets:
                del self._secrets[name]
                return True
            return False

    def list(self) -> list[str]:
        """List all secret names."""
        with self._lock:
            return list(self._secrets.keys())

    def exists(self, name: str) -> bool:
        """Check if a secret exists."""
        with self._lock:
            return name in self._secrets

    def clear(self) -> None:
        """Clear all secrets."""
        with self._lock:
            self._secrets.clear()


class FileBackend(SecretBackend):
    """File-based secret storage with encryption."""

    def __init__(
        self,
        path: str | Path,
        encryption: EncryptionProvider | None = None,
    ):
        """
        Initialize file backend.

        Args:
            path: Path to secrets file
            encryption: Encryption provider (required for security)
        """
        self._path = Path(path)
        self._encryption = encryption
        self._lock = threading.RLock()
        self._cache: dict[str, Secret] = {}
        self._loaded = False

    def _load(self) -> None:
        """Load secrets from file."""
        if self._loaded:
            return

        if not self._path.exists():
            self._loaded = True
            return

        with self._lock:
            try:
                content = self._path.read_text()
                if self._encryption:
                    content = self._encryption.decrypt(content)

                data = json.loads(content)
                for name, secret_data in data.items():
                    metadata = SecretMetadata.from_dict(secret_data["metadata"])
                    self._cache[name] = Secret(
                        value=secret_data["value"],
                        metadata=metadata,
                        encrypted=False,
                    )
                self._loaded = True
            except (OSError, ValueError, json.JSONDecodeError) as e:
                logger.error(f"Failed to load secrets: {e}")
                self._loaded = True

    def _save(self) -> None:
        """Save secrets to file."""
        with self._lock:
            data = {}
            for name, secret in self._cache.items():
                data[name] = {
                    "value": secret.value,
                    "metadata": secret.metadata.to_dict(),
                }

            content = json.dumps(data, indent=2)
            if self._encryption:
                content = self._encryption.encrypt(content)

            # Create directory if needed
            self._path.parent.mkdir(parents=True, exist_ok=True)

            # Write atomically
            tmp_path = self._path.with_suffix(".tmp")
            tmp_path.write_text(content)
            tmp_path.replace(self._path)

            # Set restrictive permissions
            os.chmod(self._path, 0o600)

    def get(self, name: str) -> Secret | None:
        """Get a secret by name."""
        self._load()
        with self._lock:
            return self._cache.get(name)

    def set(self, secret: Secret) -> None:
        """Store a secret."""
        self._load()
        with self._lock:
            self._cache[secret.metadata.name] = secret
            self._save()

    def delete(self, name: str) -> bool:
        """Delete a secret by name."""
        self._load()
        with self._lock:
            if name in self._cache:
                del self._cache[name]
                self._save()
                return True
            return False

    def list(self) -> list[str]:
        """List all secret names."""
        self._load()
        with self._lock:
            return list(self._cache.keys())

    def exists(self, name: str) -> bool:
        """Check if a secret exists."""
        self._load()
        with self._lock:
            return name in self._cache


class EnvironmentBackend(SecretBackend):
    """Environment variable backend (read-only)."""

    def __init__(self, prefix: str = ""):
        """
        Initialize environment backend.

        Args:
            prefix: Optional prefix for environment variables
        """
        self._prefix = prefix

    def _env_name(self, name: str) -> str:
        """Convert secret name to environment variable name."""
        env_name = name.upper().replace("-", "_").replace(".", "_")
        if self._prefix:
            return f"{self._prefix}{env_name}"
        return env_name

    def get(self, name: str) -> Secret | None:
        """Get a secret from environment."""
        env_name = self._env_name(name)
        value = os.environ.get(env_name)
        if value is None:
            return None

        return Secret(
            value=value,
            metadata=SecretMetadata(
                name=name,
                secret_type=SecretType.GENERIC,
                description=f"From environment variable {env_name}",
            ),
        )

    def set(self, secret: Secret) -> None:
        """Set environment variable."""
        env_name = self._env_name(secret.metadata.name)
        os.environ[env_name] = secret.value

    def delete(self, name: str) -> bool:
        """Delete environment variable."""
        env_name = self._env_name(name)
        if env_name in os.environ:
            del os.environ[env_name]
            return True
        return False

    def list(self) -> list[str]:
        """List secrets from environment with matching prefix."""
        secrets = []
        for key in os.environ:
            if self._prefix and key.startswith(self._prefix):
                name = key[len(self._prefix) :].lower().replace("_", "-")
                secrets.append(name)
            elif not self._prefix:
                secrets.append(key.lower().replace("_", "-"))
        return secrets

    def exists(self, name: str) -> bool:
        """Check if environment variable exists."""
        env_name = self._env_name(name)
        return env_name in os.environ


@dataclass
class RotationPolicy:
    """Policy for automatic secret rotation."""

    name: str
    interval: timedelta
    generator: Callable[[], str] | None = None
    notify_before: timedelta | None = None
    auto_rotate: bool = False

    def should_rotate(self, secret: Secret) -> bool:
        """Check if secret should be rotated based on policy."""
        last_rotated = secret.metadata.last_rotated or secret.metadata.created_at
        return datetime.now() - last_rotated > self.interval

    def days_until_rotation(self, secret: Secret) -> int:
        """Calculate days until rotation is needed."""
        last_rotated = secret.metadata.last_rotated or secret.metadata.created_at
        rotation_date = last_rotated + self.interval
        delta = rotation_date - datetime.now()
        return max(0, delta.days)


class SecretValidator:
    """Validates secret values against patterns and rules."""

    # Common patterns
    PATTERNS = {
        SecretType.API_KEY: r"^[A-Za-z0-9_\-]{20,}$",
        SecretType.PASSWORD: r"^.{8,}$",
        SecretType.TOKEN: r"^[A-Za-z0-9_\-\.]+$",
        SecretType.SSH_KEY: r"^-----BEGIN .+ PRIVATE KEY-----",
        SecretType.CERTIFICATE: r"^-----BEGIN CERTIFICATE-----",
    }

    def __init__(self, custom_patterns: dict[SecretType, str] | None = None):
        """Initialize with optional custom patterns."""
        self._patterns = dict(self.PATTERNS)
        if custom_patterns:
            self._patterns.update(custom_patterns)

    def validate(self, value: str, secret_type: SecretType) -> tuple[bool, str]:
        """
        Validate a secret value.

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not value:
            return False, "Secret value cannot be empty"

        pattern = self._patterns.get(secret_type)
        if pattern and not re.match(pattern, value, re.MULTILINE):
            return (
                False,
                f"Value does not match expected pattern for {secret_type.value}",
            )

        return True, ""

    def check_strength(self, value: str) -> dict[str, Any]:
        """Check password/secret strength."""
        result = {
            "length": len(value),
            "has_upper": bool(re.search(r"[A-Z]", value)),
            "has_lower": bool(re.search(r"[a-z]", value)),
            "has_digit": bool(re.search(r"\d", value)),
            "has_special": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", value)),
            "score": 0,
        }

        # Calculate score
        if result["length"] >= 8:
            result["score"] += 1
        if result["length"] >= 12:
            result["score"] += 1
        if result["length"] >= 16:
            result["score"] += 1
        if result["has_upper"]:
            result["score"] += 1
        if result["has_lower"]:
            result["score"] += 1
        if result["has_digit"]:
            result["score"] += 1
        if result["has_special"]:
            result["score"] += 1

        # Classify strength
        if result["score"] >= 6:
            result["strength"] = "strong"
        elif result["score"] >= 4:
            result["strength"] = "medium"
        else:
            result["strength"] = "weak"

        return result


class SecretGenerator:
    """Generate secure random secrets."""

    ALPHANUMERIC = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    SPECIAL = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    HEX = "0123456789abcdef"

    @classmethod
    def password(cls, length: int = 16, include_special: bool = True) -> str:
        """Generate a random password."""
        chars = cls.ALPHANUMERIC
        if include_special:
            chars += cls.SPECIAL

        # Ensure at least one of each type
        result = [
            cls._random_choice(cls.ALPHANUMERIC[:26]),  # lowercase
            cls._random_choice(cls.ALPHANUMERIC[26:52]),  # uppercase
            cls._random_choice(cls.ALPHANUMERIC[52:]),  # digit
        ]
        if include_special:
            result.append(cls._random_choice(cls.SPECIAL))

        # Fill remaining length
        while len(result) < length:
            result.append(cls._random_choice(chars))

        # Shuffle
        result_bytes = bytearray(c.encode()[0] for c in result)
        for i in range(len(result_bytes) - 1, 0, -1):
            j = int.from_bytes(os.urandom(1), "big") % (i + 1)
            result_bytes[i], result_bytes[j] = result_bytes[j], result_bytes[i]

        return result_bytes.decode()

    @classmethod
    def api_key(cls, length: int = 32, prefix: str = "") -> str:
        """Generate a random API key."""
        key = "".join(cls._random_choice(cls.ALPHANUMERIC) for _ in range(length))
        if prefix:
            return f"{prefix}_{key}"
        return key

    @classmethod
    def token(cls, length: int = 64) -> str:
        """Generate a random token (URL-safe base64)."""
        return base64.urlsafe_b64encode(os.urandom(length)).decode()[:length]

    @classmethod
    def hex_key(cls, length: int = 32) -> str:
        """Generate a random hex key."""
        return os.urandom(length // 2).hex()

    @classmethod
    def uuid(cls) -> str:
        """Generate a random UUID v4."""
        random_bytes = os.urandom(16)
        # Set version (4) and variant bits
        random_bytes = bytearray(random_bytes)
        random_bytes[6] = (random_bytes[6] & 0x0F) | 0x40
        random_bytes[8] = (random_bytes[8] & 0x3F) | 0x80

        hex_str = random_bytes.hex()
        return f"{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:]}"

    @classmethod
    def _random_choice(cls, chars: str) -> str:
        """Securely choose a random character."""
        idx = int.from_bytes(os.urandom(1), "big") % len(chars)
        return chars[idx]


class AuditLog:
    """Audit log for secret access and modifications."""

    def __init__(self, path: str | Path | None = None):
        """Initialize audit log."""
        self._path = Path(path) if path else None
        self._entries: list[dict[str, Any]] = []
        self._lock = threading.RLock()

    def log(
        self,
        action: str,
        secret_name: str,
        user: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log an action."""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "secret_name": secret_name,
            "user": user or os.environ.get("USER", "unknown"),
            "details": details or {},
        }

        with self._lock:
            self._entries.append(entry)

            if self._path:
                with self._path.open("a") as f:
                    f.write(json.dumps(entry) + "\n")

    def get_entries(
        self,
        secret_name: str | None = None,
        action: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query audit log entries."""
        with self._lock:
            entries = self._entries.copy()

        # Filter
        if secret_name:
            entries = [e for e in entries if e["secret_name"] == secret_name]
        if action:
            entries = [e for e in entries if e["action"] == action]
        if since:
            entries = [
                e for e in entries if datetime.fromisoformat(e["timestamp"]) >= since
            ]

        # Return most recent first, limited
        return sorted(entries, key=lambda e: e["timestamp"], reverse=True)[:limit]


class SecretsManager:
    """
    Main secrets manager for secure credential storage and access.

    Features:
    - Multiple backends (memory, file, environment)
    - Encryption at rest
    - Key rotation
    - Secret versioning
    - Access auditing
    - Expiration handling
    - Rotation policies
    """

    def __init__(
        self,
        backend: SecretBackend | None = None,
        encryption: EncryptionProvider | None = None,
        audit_log: AuditLog | None = None,
        validator: SecretValidator | None = None,
    ):
        """
        Initialize secrets manager.

        Args:
            backend: Storage backend (default: MemoryBackend)
            encryption: Encryption provider for values
            audit_log: Optional audit log
            validator: Optional secret validator
        """
        self._backend = backend or MemoryBackend()
        self._encryption = encryption
        self._audit = audit_log or AuditLog()
        self._validator = validator or SecretValidator()
        self._rotation_policies: dict[str, RotationPolicy] = {}
        self._access_callbacks: list[Callable[[str, Secret], None]] = []
        self._lock = threading.RLock()

    def set(
        self,
        name: str,
        value: str,
        secret_type: SecretType = SecretType.GENERIC,
        expires_at: datetime | None = None,
        tags: dict[str, str] | None = None,
        description: str = "",
        validate: bool = True,
    ) -> Secret:
        """
        Store a secret.

        Args:
            name: Secret name
            value: Secret value
            secret_type: Type of secret
            expires_at: Optional expiration time
            tags: Optional key-value tags
            description: Optional description
            validate: Whether to validate the value

        Returns:
            The stored secret
        """
        if validate:
            is_valid, error = self._validator.validate(value, secret_type)
            if not is_valid:
                raise ValueError(f"Invalid secret value: {error}")

        # Check for existing secret (versioning)
        existing = self._backend.get(name)
        version = 1
        if existing:
            version = existing.metadata.version + 1

        # Encrypt if provider available
        stored_value = value
        encrypted = False
        if self._encryption:
            stored_value = self._encryption.encrypt(value)
            encrypted = True

        metadata = SecretMetadata(
            name=name,
            secret_type=secret_type,
            expires_at=expires_at,
            version=version,
            tags=tags or {},
            description=description,
        )

        secret = Secret(value=stored_value, metadata=metadata, encrypted=encrypted)

        with self._lock:
            self._backend.set(secret)

        self._audit.log(
            "set", name, details={"version": version, "encrypted": encrypted}
        )

        return Secret(value=value, metadata=metadata, encrypted=False)

    def get(self, name: str, default: str | None = None) -> str | None:
        """
        Get a secret value.

        Args:
            name: Secret name
            default: Default value if not found

        Returns:
            Secret value or default
        """
        secret = self.get_secret(name)
        if secret is None:
            return default
        return secret.value

    def get_secret(self, name: str) -> Secret | None:
        """
        Get a secret with metadata.

        Args:
            name: Secret name

        Returns:
            Secret object or None
        """
        with self._lock:
            secret = self._backend.get(name)

        if secret is None:
            return None

        # Check expiration
        if secret.metadata.is_expired():
            self._audit.log("access_expired", name)
            return None

        # Decrypt if needed
        value = secret.value
        if secret.encrypted and self._encryption:
            value = self._encryption.decrypt(secret.value)

        # Update access tracking
        secret.metadata.access_count += 1
        secret.metadata.last_accessed = datetime.now()

        # Create decrypted copy
        result = Secret(
            value=value,
            metadata=secret.metadata,
            encrypted=False,
        )

        # Notify callbacks — broad guard is intentional: user-provided callbacks must
        # not break secret retrieval regardless of what they raise.
        for callback in self._access_callbacks:
            try:
                callback(name, result)
            except Exception as e:  # noqa: BLE001
                logger.warning(f"Access callback failed: {e}")

        self._audit.log("get", name)

        return result

    def delete(self, name: str) -> bool:
        """Delete a secret."""
        with self._lock:
            deleted = self._backend.delete(name)

        if deleted:
            self._audit.log("delete", name)

        return deleted

    def exists(self, name: str) -> bool:
        """Check if a secret exists."""
        return self._backend.exists(name)

    def list(
        self, prefix: str | None = None, tags: dict[str, str] | None = None
    ) -> list[str]:
        """
        List secret names.

        Args:
            prefix: Optional name prefix filter
            tags: Optional tag filter

        Returns:
            List of secret names
        """
        names = self._backend.list()

        if prefix:
            names = [n for n in names if n.startswith(prefix)]

        if tags:
            filtered = []
            for name in names:
                secret = self._backend.get(name)
                if secret and all(
                    secret.metadata.tags.get(k) == v for k, v in tags.items()
                ):
                    filtered.append(name)
            names = filtered

        return sorted(names)

    def rotate(
        self,
        name: str,
        new_value: str | None = None,
        generator: Callable[[], str] | None = None,
    ) -> Secret:
        """
        Rotate a secret.

        Args:
            name: Secret name
            new_value: New value (or use generator)
            generator: Callable to generate new value

        Returns:
            Updated secret
        """
        secret = self.get_secret(name)
        if secret is None:
            raise KeyError(f"Secret not found: {name}")

        # Generate new value
        if new_value is None:
            if generator:
                new_value = generator()
            elif name in self._rotation_policies:
                policy = self._rotation_policies[name]
                if policy.generator:
                    new_value = policy.generator()

            if new_value is None:
                # Default generator based on type
                if secret.metadata.secret_type == SecretType.API_KEY:
                    new_value = SecretGenerator.api_key()
                elif secret.metadata.secret_type == SecretType.PASSWORD:
                    new_value = SecretGenerator.password()
                elif secret.metadata.secret_type == SecretType.TOKEN:
                    new_value = SecretGenerator.token()
                else:
                    new_value = SecretGenerator.password(32)

        # Store new value
        result = self.set(
            name=name,
            value=new_value,
            secret_type=secret.metadata.secret_type,
            expires_at=secret.metadata.expires_at,
            tags=secret.metadata.tags,
            description=secret.metadata.description,
            validate=False,
        )

        # Update rotation timestamp
        result.metadata.last_rotated = datetime.now()

        self._audit.log("rotate", name, details={"version": result.metadata.version})

        return result

    def set_rotation_policy(self, name: str, policy: RotationPolicy) -> None:
        """Set rotation policy for a secret."""
        self._rotation_policies[name] = policy

    def check_rotation_needed(self) -> list[str]:
        """Check which secrets need rotation."""
        needs_rotation = []

        for name, policy in self._rotation_policies.items():
            secret = self.get_secret(name)
            if secret and policy.should_rotate(secret):
                needs_rotation.append(name)

        return needs_rotation

    def rotate_encryption_key(self) -> int:
        """
        Rotate the encryption key and re-encrypt all secrets.

        Returns:
            Number of secrets re-encrypted
        """
        if not self._encryption:
            raise RuntimeError("No encryption provider configured")

        # Get all secrets (decrypted)
        secrets_to_reencrypt = []
        for name in self._backend.list():
            secret = self.get_secret(name)
            if secret:
                secrets_to_reencrypt.append(secret)

        # Rotate key
        self._encryption.rotate_key()

        # Re-encrypt all secrets
        count = 0
        for secret in secrets_to_reencrypt:
            encrypted_value = self._encryption.encrypt(secret.value)
            stored = Secret(
                value=encrypted_value,
                metadata=secret.metadata,
                encrypted=True,
            )
            self._backend.set(stored)
            count += 1

        self._audit.log("rotate_key", "*", details={"secrets_count": count})

        return count

    def on_access(self, callback: Callable[[str, Secret], None]) -> None:
        """Register a callback for secret access."""
        self._access_callbacks.append(callback)

    def get_audit_log(
        self,
        secret_name: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Get audit log entries."""
        return self._audit.get_entries(secret_name=secret_name, limit=limit)

    def check_expiring(self, within: timedelta = timedelta(days=7)) -> list[str]:
        """Find secrets expiring within the given timeframe."""
        expiring = []
        cutoff = datetime.now() + within

        for name in self._backend.list():
            secret = self._backend.get(name)
            if secret and secret.metadata.expires_at:
                if secret.metadata.expires_at <= cutoff:
                    expiring.append(name)

        return expiring

    def import_from_env(
        self,
        prefix: str = "",
        secret_type: SecretType = SecretType.GENERIC,
        pattern: str | None = None,
    ) -> int:
        """
        Import secrets from environment variables.

        Args:
            prefix: Environment variable prefix
            secret_type: Type to assign to imported secrets
            pattern: Optional regex pattern for variable names

        Returns:
            Number of secrets imported
        """
        count = 0
        compiled_pattern = re.compile(pattern) if pattern else None

        for key, value in os.environ.items():
            if prefix and not key.startswith(prefix):
                continue
            if compiled_pattern and not compiled_pattern.match(key):
                continue

            # Convert env var name to secret name
            name = key
            if prefix:
                name = key[len(prefix) :]
            name = name.lower().replace("_", "-")

            self.set(
                name=name,
                value=value,
                secret_type=secret_type,
                description=f"Imported from environment variable {key}",
                validate=False,
            )
            count += 1

        return count

    def export_to_env(self, prefix: str = "", names: list[str] | None = None) -> int:
        """
        Export secrets to environment variables.

        Args:
            prefix: Prefix for environment variable names
            names: Optional list of secret names (default: all)

        Returns:
            Number of secrets exported
        """
        count = 0
        secret_names = names or self._backend.list()

        for name in secret_names:
            secret = self.get_secret(name)
            if secret:
                env_name = name.upper().replace("-", "_").replace(".", "_")
                if prefix:
                    env_name = f"{prefix}{env_name}"
                os.environ[env_name] = secret.value
                count += 1

        return count


# Convenience functions


def create_secrets_manager(
    backend_type: str = "memory",
    path: str | None = None,
    encryption_key: str | None = None,
    audit_path: str | None = None,
) -> SecretsManager:
    """
    Create a secrets manager with common configuration.

    Args:
        backend_type: "memory", "file", or "env"
        path: Path for file backend
        encryption_key: Encryption key (generates if None)
        audit_path: Path for audit log
    """
    # Set up encryption
    encryption = None
    if encryption_key:
        try:
            encryption = FernetEncryption(encryption_key.encode())
        except ImportError:
            raise ImportError(
                "The 'cryptography' package is required for encryption. "
                "Install it with: pip install cryptography"
            )
    elif backend_type == "file":
        try:
            encryption = FernetEncryption()
        except ImportError:
            raise ImportError(
                "The 'cryptography' package is required for file-backed secrets. "
                "Install it with: pip install cryptography"
            )

    # Set up backend
    if backend_type == "memory":
        backend = MemoryBackend()
    elif backend_type == "file":
        if not path:
            raise ValueError("path required for file backend")
        backend = FileBackend(path, encryption)
    elif backend_type == "env":
        backend = EnvironmentBackend()
    else:
        raise ValueError(f"Unknown backend type: {backend_type}")

    # Set up audit log
    audit = AuditLog(audit_path) if audit_path else AuditLog()

    return SecretsManager(
        backend=backend,
        encryption=encryption,
        audit_log=audit,
    )


def mask_secret(value: str, show_chars: int = 4) -> str:
    """Mask a secret value for display."""
    if len(value) <= show_chars:
        return "*" * len(value)
    return value[:show_chars] + "*" * (len(value) - show_chars)


def generate_password(length: int = 16, include_special: bool = True) -> str:
    """Generate a random password."""
    return SecretGenerator.password(length, include_special)


def generate_api_key(length: int = 32, prefix: str = "") -> str:
    """Generate a random API key."""
    return SecretGenerator.api_key(length, prefix)


def generate_token(length: int = 64) -> str:
    """Generate a random token."""
    return SecretGenerator.token(length)


def hash_secret(value: str, salt: str | None = None) -> str:
    """
    Create a secure hash of a secret value.

    Args:
        value: Secret value to hash
        salt: Optional salt (generates random if None)

    Returns:
        Hash in format "salt$hash"
    """
    if salt is None:
        salt = base64.urlsafe_b64encode(os.urandom(16)).decode()

    hash_value = hashlib.pbkdf2_hmac(
        "sha256",
        value.encode(),
        salt.encode(),
        100000,
    )

    return f"{salt}${base64.urlsafe_b64encode(hash_value).decode()}"


def verify_secret_hash(value: str, hashed: str) -> bool:
    """
    Verify a secret against its hash.

    Args:
        value: Secret value to verify
        hashed: Hash in format "salt$hash"

    Returns:
        True if value matches hash
    """
    try:
        salt, expected_hash = hashed.split("$", 1)
        actual = hash_secret(value, salt)
        return hmac.compare_digest(actual, hashed)
    except (ValueError, TypeError):
        return False
