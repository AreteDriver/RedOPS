"""Tests for secrets manager module."""

import os
import tempfile
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from redops.core.secrets import (
    # Enums
    SecretType,
    EncryptionAlgorithm,
    # Data classes
    SecretMetadata,
    Secret,
    RotationPolicy,
    # Encryption
    EncryptionProvider,
    FernetEncryption,
    # Backends
    SecretBackend,
    MemoryBackend,
    FileBackend,
    EnvironmentBackend,
    # Core classes
    SecretValidator,
    SecretGenerator,
    AuditLog,
    SecretsManager,
    # Convenience functions
    create_secrets_manager,
    mask_secret,
    generate_password,
    generate_api_key,
    generate_token,
    hash_secret,
    verify_secret_hash,
)


# =============================================================================
# SecretType Tests
# =============================================================================

class TestSecretType:
    """Tests for SecretType enum."""

    def test_all_types(self):
        """Test all secret types exist."""
        assert SecretType.API_KEY.value == "api_key"
        assert SecretType.PASSWORD.value == "password"
        assert SecretType.TOKEN.value == "token"
        assert SecretType.CERTIFICATE.value == "certificate"
        assert SecretType.PRIVATE_KEY.value == "private_key"
        assert SecretType.CONNECTION_STRING.value == "connection_string"
        assert SecretType.OAUTH_TOKEN.value == "oauth_token"
        assert SecretType.SSH_KEY.value == "ssh_key"
        assert SecretType.GENERIC.value == "generic"


class TestEncryptionAlgorithm:
    """Tests for EncryptionAlgorithm enum."""

    def test_all_algorithms(self):
        """Test all encryption algorithms exist."""
        assert EncryptionAlgorithm.AES_256_GCM.value == "aes-256-gcm"
        assert EncryptionAlgorithm.AES_256_CBC.value == "aes-256-cbc"
        assert EncryptionAlgorithm.CHACHA20_POLY1305.value == "chacha20-poly1305"
        assert EncryptionAlgorithm.FERNET.value == "fernet"


# =============================================================================
# SecretMetadata Tests
# =============================================================================

class TestSecretMetadata:
    """Tests for SecretMetadata dataclass."""

    def test_create_basic(self):
        """Test basic metadata creation."""
        meta = SecretMetadata(name="test-secret")
        assert meta.name == "test-secret"
        assert meta.secret_type == SecretType.GENERIC
        assert meta.version == 1
        assert meta.access_count == 0

    def test_create_with_all_fields(self):
        """Test metadata with all fields."""
        expires = datetime.now() + timedelta(days=30)
        meta = SecretMetadata(
            name="api-key",
            secret_type=SecretType.API_KEY,
            expires_at=expires,
            version=3,
            tags={"env": "prod"},
            description="Production API key",
            rotation_policy="30d",
        )
        assert meta.name == "api-key"
        assert meta.secret_type == SecretType.API_KEY
        assert meta.expires_at == expires
        assert meta.version == 3
        assert meta.tags == {"env": "prod"}
        assert meta.description == "Production API key"

    def test_is_expired_no_expiration(self):
        """Test is_expired with no expiration."""
        meta = SecretMetadata(name="test")
        assert not meta.is_expired()

    def test_is_expired_future(self):
        """Test is_expired with future date."""
        meta = SecretMetadata(
            name="test",
            expires_at=datetime.now() + timedelta(days=30),
        )
        assert not meta.is_expired()

    def test_is_expired_past(self):
        """Test is_expired with past date."""
        meta = SecretMetadata(
            name="test",
            expires_at=datetime.now() - timedelta(days=1),
        )
        assert meta.is_expired()

    def test_to_dict(self):
        """Test conversion to dictionary."""
        meta = SecretMetadata(
            name="test",
            secret_type=SecretType.PASSWORD,
            version=2,
            tags={"env": "dev"},
        )
        data = meta.to_dict()
        assert data["name"] == "test"
        assert data["secret_type"] == "password"
        assert data["version"] == 2
        assert data["tags"] == {"env": "dev"}

    def test_from_dict(self):
        """Test creation from dictionary."""
        data = {
            "name": "test",
            "secret_type": "api_key",
            "version": 5,
            "tags": {"service": "auth"},
            "created_at": "2024-01-01T00:00:00",
            "updated_at": "2024-01-02T00:00:00",
        }
        meta = SecretMetadata.from_dict(data)
        assert meta.name == "test"
        assert meta.secret_type == SecretType.API_KEY
        assert meta.version == 5
        assert meta.tags == {"service": "auth"}

    def test_from_dict_minimal(self):
        """Test creation from minimal dictionary."""
        data = {"name": "minimal"}
        meta = SecretMetadata.from_dict(data)
        assert meta.name == "minimal"
        assert meta.secret_type == SecretType.GENERIC
        assert meta.version == 1


# =============================================================================
# Secret Tests
# =============================================================================

class TestSecret:
    """Tests for Secret dataclass."""

    def test_create(self):
        """Test secret creation."""
        meta = SecretMetadata(name="test")
        secret = Secret(value="secret123", metadata=meta)
        assert secret.value == "secret123"
        assert secret.metadata.name == "test"
        assert not secret.encrypted

    def test_repr_hides_value(self):
        """Test repr doesn't expose value."""
        meta = SecretMetadata(name="test", secret_type=SecretType.PASSWORD)
        secret = Secret(value="supersecret", metadata=meta)
        repr_str = repr(secret)
        assert "supersecret" not in repr_str
        assert "test" in repr_str

    def test_str_hides_value(self):
        """Test str doesn't expose value."""
        meta = SecretMetadata(name="test")
        secret = Secret(value="supersecret", metadata=meta)
        str_val = str(secret)
        assert "supersecret" not in str_val

    def test_mask(self):
        """Test value masking."""
        meta = SecretMetadata(name="test")
        secret = Secret(value="supersecret123", metadata=meta)
        assert secret.mask(4) == "supe**********"

    def test_mask_short_value(self):
        """Test masking short values."""
        meta = SecretMetadata(name="test")
        secret = Secret(value="abc", metadata=meta)
        assert secret.mask(4) == "***"


# =============================================================================
# =============================================================================
# FernetEncryption Tests
# =============================================================================

class TestFernetEncryption:
    """Tests for FernetEncryption provider."""

    @pytest.fixture
    def fernet(self):
        """Create Fernet encryption if available."""
        try:
            return FernetEncryption()
        except ImportError:
            pytest.skip("cryptography package not installed")

    def test_encrypt_decrypt(self, fernet):
        """Test basic encryption and decryption."""
        plaintext = "my secret value"

        ciphertext = fernet.encrypt(plaintext)
        assert ciphertext != plaintext

        decrypted = fernet.decrypt(ciphertext)
        assert decrypted == plaintext

    def test_key_property(self, fernet):
        """Test key property."""
        assert fernet.key is not None
        assert isinstance(fernet.key, bytes)

    def test_rotate_key(self, fernet):
        """Test key rotation."""
        plaintext = "test value"
        ciphertext = fernet.encrypt(plaintext)

        old_key = fernet.key
        fernet.rotate_key()
        assert fernet.key != old_key

        # Should still decrypt
        decrypted = fernet.decrypt(ciphertext)
        assert decrypted == plaintext


# =============================================================================
# MemoryBackend Tests
# =============================================================================

class TestMemoryBackend:
    """Tests for MemoryBackend."""

    @pytest.fixture
    def backend(self):
        """Create memory backend."""
        return MemoryBackend()

    def test_set_get(self, backend):
        """Test basic set and get."""
        meta = SecretMetadata(name="test")
        secret = Secret(value="value", metadata=meta)

        backend.set(secret)
        retrieved = backend.get("test")

        assert retrieved is not None
        assert retrieved.value == "value"

    def test_get_nonexistent(self, backend):
        """Test getting nonexistent secret."""
        assert backend.get("nonexistent") is None

    def test_exists(self, backend):
        """Test exists check."""
        meta = SecretMetadata(name="test")
        secret = Secret(value="value", metadata=meta)

        assert not backend.exists("test")
        backend.set(secret)
        assert backend.exists("test")

    def test_delete(self, backend):
        """Test secret deletion."""
        meta = SecretMetadata(name="test")
        secret = Secret(value="value", metadata=meta)

        backend.set(secret)
        assert backend.exists("test")

        assert backend.delete("test")
        assert not backend.exists("test")

    def test_delete_nonexistent(self, backend):
        """Test deleting nonexistent secret."""
        assert not backend.delete("nonexistent")

    def test_list(self, backend):
        """Test listing secrets."""
        for i in range(3):
            meta = SecretMetadata(name=f"secret-{i}")
            backend.set(Secret(value="v", metadata=meta))

        names = backend.list()
        assert len(names) == 3
        assert "secret-0" in names
        assert "secret-1" in names
        assert "secret-2" in names

    def test_clear(self, backend):
        """Test clearing all secrets."""
        for i in range(3):
            meta = SecretMetadata(name=f"secret-{i}")
            backend.set(Secret(value="v", metadata=meta))

        backend.clear()
        assert len(backend.list()) == 0

    def test_thread_safety(self, backend):
        """Test thread-safe access."""
        errors = []

        def writer():
            try:
                for i in range(100):
                    meta = SecretMetadata(name=f"thread-{threading.current_thread().name}-{i}")
                    backend.set(Secret(value="v", metadata=meta))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors


# =============================================================================
# FileBackend Tests
# =============================================================================

class TestFileBackend:
    """Tests for FileBackend."""

    @pytest.fixture
    def temp_file(self):
        """Create temporary file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
            yield f.name
        os.unlink(f.name)

    def test_set_get(self, temp_file):
        """Test basic set and get."""
        backend = FileBackend(temp_file, FernetEncryption())

        meta = SecretMetadata(name="test")
        secret = Secret(value="value", metadata=meta)

        backend.set(secret)
        retrieved = backend.get("test")

        assert retrieved is not None
        assert retrieved.value == "value"

    def test_persistence(self, temp_file):
        """Test secrets persist across instances."""
        enc = FernetEncryption()

        # Write with first instance
        backend1 = FileBackend(temp_file, enc)
        meta = SecretMetadata(name="test")
        backend1.set(Secret(value="persistent", metadata=meta))

        # Read with second instance
        backend2 = FileBackend(temp_file, enc)
        retrieved = backend2.get("test")

        assert retrieved is not None
        assert retrieved.value == "persistent"

    def test_delete(self, temp_file):
        """Test secret deletion."""
        backend = FileBackend(temp_file, FernetEncryption())

        meta = SecretMetadata(name="test")
        backend.set(Secret(value="value", metadata=meta))

        assert backend.delete("test")
        assert not backend.exists("test")

    def test_list(self, temp_file):
        """Test listing secrets."""
        backend = FileBackend(temp_file, FernetEncryption())

        for i in range(3):
            meta = SecretMetadata(name=f"secret-{i}")
            backend.set(Secret(value="v", metadata=meta))

        names = backend.list()
        assert len(names) == 3

    def test_creates_parent_directory(self):
        """Test creates parent directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "subdir" / "secrets.json"
            backend = FileBackend(path, FernetEncryption())

            meta = SecretMetadata(name="test")
            backend.set(Secret(value="value", metadata=meta))

            assert path.exists()


# =============================================================================
# EnvironmentBackend Tests
# =============================================================================

class TestEnvironmentBackend:
    """Tests for EnvironmentBackend."""

    def test_get_from_env(self):
        """Test getting secret from environment."""
        backend = EnvironmentBackend()

        with patch.dict(os.environ, {"TEST_SECRET": "value123"}):
            secret = backend.get("test-secret")
            assert secret is not None
            assert secret.value == "value123"

    def test_get_with_prefix(self):
        """Test getting secret with prefix."""
        backend = EnvironmentBackend(prefix="APP_")

        with patch.dict(os.environ, {"APP_DATABASE_URL": "postgres://..."}):
            secret = backend.get("database-url")
            assert secret is not None
            assert secret.value == "postgres://..."

    def test_set_to_env(self):
        """Test setting environment variable."""
        backend = EnvironmentBackend()

        meta = SecretMetadata(name="new-var")
        secret = Secret(value="newvalue", metadata=meta)

        backend.set(secret)
        assert os.environ.get("NEW_VAR") == "newvalue"

        # Cleanup
        del os.environ["NEW_VAR"]

    def test_delete_from_env(self):
        """Test deleting environment variable."""
        backend = EnvironmentBackend()

        with patch.dict(os.environ, {"DELETE_ME": "value"}):
            assert backend.delete("delete-me")
            assert "DELETE_ME" not in os.environ

    def test_exists(self):
        """Test exists check."""
        backend = EnvironmentBackend()

        with patch.dict(os.environ, {"EXISTS_VAR": "value"}):
            assert backend.exists("exists-var")
            assert not backend.exists("not-exists")


# =============================================================================
# SecretValidator Tests
# =============================================================================

class TestSecretValidator:
    """Tests for SecretValidator."""

    @pytest.fixture
    def validator(self):
        """Create validator."""
        return SecretValidator()

    def test_validate_empty(self, validator):
        """Test empty value validation."""
        is_valid, error = validator.validate("", SecretType.GENERIC)
        assert not is_valid
        assert "empty" in error.lower()

    def test_validate_api_key_valid(self, validator):
        """Test valid API key."""
        is_valid, _ = validator.validate("api_key_abcdefgh12345678901234", SecretType.API_KEY)
        assert is_valid

    def test_validate_api_key_invalid(self, validator):
        """Test invalid API key (too short)."""
        is_valid, error = validator.validate("short", SecretType.API_KEY)
        assert not is_valid
        assert "pattern" in error.lower()

    def test_validate_password_valid(self, validator):
        """Test valid password."""
        is_valid, _ = validator.validate("MySecureP@ss123", SecretType.PASSWORD)
        assert is_valid

    def test_validate_password_too_short(self, validator):
        """Test password too short."""
        is_valid, _ = validator.validate("short", SecretType.PASSWORD)
        assert not is_valid

    def test_check_strength_weak(self, validator):
        """Test weak password strength."""
        result = validator.check_strength("password")
        assert result["strength"] == "weak"
        assert result["score"] < 4

    def test_check_strength_medium(self, validator):
        """Test medium password strength."""
        result = validator.check_strength("Password123")
        assert result["strength"] == "medium"

    def test_check_strength_strong(self, validator):
        """Test strong password strength."""
        result = validator.check_strength("MyStr0ng!P@ssword123")
        assert result["strength"] == "strong"
        assert result["score"] >= 6

    def test_check_strength_characteristics(self, validator):
        """Test strength check characteristics."""
        result = validator.check_strength("Ab1!")
        assert result["has_upper"]
        assert result["has_lower"]
        assert result["has_digit"]
        assert result["has_special"]


# =============================================================================
# SecretGenerator Tests
# =============================================================================

class TestSecretGenerator:
    """Tests for SecretGenerator."""

    def test_password_length(self):
        """Test password generation length."""
        password = SecretGenerator.password(20)
        assert len(password) == 20

    def test_password_has_variety(self):
        """Test password has character variety."""
        password = SecretGenerator.password(16)
        assert any(c.isupper() for c in password)
        assert any(c.islower() for c in password)
        assert any(c.isdigit() for c in password)

    def test_password_with_special(self):
        """Test password with special characters."""
        password = SecretGenerator.password(16, include_special=True)
        assert any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

    def test_password_without_special(self):
        """Test password without special characters."""
        password = SecretGenerator.password(16, include_special=False)
        assert all(c.isalnum() for c in password)

    def test_api_key_length(self):
        """Test API key generation length."""
        key = SecretGenerator.api_key(32)
        assert len(key) == 32

    def test_api_key_with_prefix(self):
        """Test API key with prefix."""
        key = SecretGenerator.api_key(32, prefix="sk_test")
        assert key.startswith("sk_test_")
        assert len(key) == 32 + len("sk_test_")

    def test_token_length(self):
        """Test token generation length."""
        token = SecretGenerator.token(64)
        assert len(token) == 64

    def test_hex_key_length(self):
        """Test hex key generation length."""
        key = SecretGenerator.hex_key(32)
        assert len(key) == 32
        assert all(c in "0123456789abcdef" for c in key)

    def test_uuid_format(self):
        """Test UUID generation format."""
        uuid = SecretGenerator.uuid()
        parts = uuid.split("-")
        assert len(parts) == 5
        assert [len(p) for p in parts] == [8, 4, 4, 4, 12]

    def test_uniqueness(self):
        """Test generated values are unique."""
        passwords = [SecretGenerator.password() for _ in range(100)]
        assert len(set(passwords)) == 100


# =============================================================================
# AuditLog Tests
# =============================================================================

class TestAuditLog:
    """Tests for AuditLog."""

    @pytest.fixture
    def audit(self):
        """Create audit log."""
        return AuditLog()

    def test_log_entry(self, audit):
        """Test logging an entry."""
        audit.log("get", "test-secret")
        entries = audit.get_entries()

        assert len(entries) == 1
        assert entries[0]["action"] == "get"
        assert entries[0]["secret_name"] == "test-secret"

    def test_log_with_details(self, audit):
        """Test logging with details."""
        audit.log("rotate", "api-key", details={"version": 2})
        entries = audit.get_entries()

        assert entries[0]["details"]["version"] == 2

    def test_filter_by_secret_name(self, audit):
        """Test filtering by secret name."""
        audit.log("get", "secret-1")
        audit.log("get", "secret-2")
        audit.log("set", "secret-1")

        entries = audit.get_entries(secret_name="secret-1")
        assert len(entries) == 2
        assert all(e["secret_name"] == "secret-1" for e in entries)

    def test_filter_by_action(self, audit):
        """Test filtering by action."""
        audit.log("get", "secret-1")
        audit.log("set", "secret-2")
        audit.log("delete", "secret-3")

        entries = audit.get_entries(action="get")
        assert len(entries) == 1
        assert entries[0]["action"] == "get"

    def test_limit(self, audit):
        """Test entry limit."""
        for i in range(10):
            audit.log("get", f"secret-{i}")

        entries = audit.get_entries(limit=5)
        assert len(entries) == 5

    def test_file_persistence(self):
        """Test audit log file persistence."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
            path = f.name

        try:
            audit = AuditLog(path)
            audit.log("get", "test")
            audit.log("set", "test2")

            # Check file was written
            with open(path) as f:
                lines = f.readlines()
                assert len(lines) == 2
        finally:
            os.unlink(path)


# =============================================================================
# RotationPolicy Tests
# =============================================================================

class TestRotationPolicy:
    """Tests for RotationPolicy."""

    def test_should_rotate_new_secret(self):
        """Test new secret doesn't need rotation."""
        policy = RotationPolicy(
            name="30-day",
            interval=timedelta(days=30),
        )

        meta = SecretMetadata(name="test")
        secret = Secret(value="value", metadata=meta)

        assert not policy.should_rotate(secret)

    def test_should_rotate_old_secret(self):
        """Test old secret needs rotation."""
        policy = RotationPolicy(
            name="30-day",
            interval=timedelta(days=30),
        )

        meta = SecretMetadata(
            name="test",
            created_at=datetime.now() - timedelta(days=45),
        )
        secret = Secret(value="value", metadata=meta)

        assert policy.should_rotate(secret)

    def test_days_until_rotation(self):
        """Test calculating days until rotation."""
        policy = RotationPolicy(
            name="30-day",
            interval=timedelta(days=30),
        )

        meta = SecretMetadata(
            name="test",
            created_at=datetime.now() - timedelta(days=10),
        )
        secret = Secret(value="value", metadata=meta)

        days = policy.days_until_rotation(secret)
        # Allow for timing boundary (19 or 20 depending on exact timing)
        assert days in (19, 20)


# =============================================================================
# SecretsManager Tests
# =============================================================================

class TestSecretsManager:
    """Tests for SecretsManager."""

    @pytest.fixture
    def manager(self):
        """Create secrets manager."""
        return SecretsManager()

    def test_set_get(self, manager):
        """Test basic set and get."""
        manager.set("test-secret", "my-value")
        value = manager.get("test-secret")
        assert value == "my-value"

    def test_get_default(self, manager):
        """Test get with default."""
        value = manager.get("nonexistent", "default")
        assert value == "default"

    def test_get_secret_with_metadata(self, manager):
        """Test get_secret returns full secret."""
        manager.set(
            "test-secret",
            "test_api_key_for_unit_testing",
            secret_type=SecretType.API_KEY,
            description="Test API key",
        )
        secret = manager.get_secret("test-secret")

        assert secret is not None
        assert secret.value == "test_api_key_for_unit_testing"
        assert secret.metadata.secret_type == SecretType.API_KEY
        assert secret.metadata.description == "Test API key"

    def test_versioning(self, manager):
        """Test secret versioning."""
        manager.set("versioned", "v1")
        secret1 = manager.get_secret("versioned")
        assert secret1.metadata.version == 1

        manager.set("versioned", "v2")
        secret2 = manager.get_secret("versioned")
        assert secret2.metadata.version == 2

    def test_delete(self, manager):
        """Test secret deletion."""
        manager.set("to-delete", "value")
        assert manager.exists("to-delete")

        manager.delete("to-delete")
        assert not manager.exists("to-delete")

    def test_list(self, manager):
        """Test listing secrets."""
        manager.set("secret-1", "v1")
        manager.set("secret-2", "v2")
        manager.set("other-3", "v3")

        names = manager.list()
        assert len(names) == 3

    def test_list_with_prefix(self, manager):
        """Test listing with prefix filter."""
        manager.set("api-key-1", "v1")
        manager.set("api-key-2", "v2")
        manager.set("database-url", "v3")

        names = manager.list(prefix="api-")
        assert len(names) == 2
        assert all(n.startswith("api-") for n in names)

    def test_list_with_tags(self, manager):
        """Test listing with tag filter."""
        manager.set("prod-key", "v1", tags={"env": "prod"})
        manager.set("dev-key", "v2", tags={"env": "dev"})
        manager.set("test-key", "v3", tags={"env": "test"})

        names = manager.list(tags={"env": "prod"})
        assert names == ["prod-key"]

    def test_expired_secret(self, manager):
        """Test expired secrets are not returned."""
        manager.set(
            "expired",
            "value",
            expires_at=datetime.now() - timedelta(days=1),
        )

        assert manager.get("expired") is None

    def test_check_expiring(self, manager):
        """Test checking for expiring secrets."""
        # Expiring soon
        manager.set(
            "expiring-soon",
            "value",
            expires_at=datetime.now() + timedelta(days=3),
        )

        # Not expiring soon
        manager.set(
            "not-expiring",
            "value",
            expires_at=datetime.now() + timedelta(days=30),
        )

        # No expiration
        manager.set("no-expiry", "value")

        expiring = manager.check_expiring(within=timedelta(days=7))
        assert "expiring-soon" in expiring
        assert "not-expiring" not in expiring
        assert "no-expiry" not in expiring

    def test_rotate(self, manager):
        """Test secret rotation."""
        manager.set("rotate-me", "old-value", secret_type=SecretType.PASSWORD)

        new_secret = manager.rotate("rotate-me", "new-value")
        assert new_secret.value == "new-value"
        assert new_secret.metadata.version == 2

    def test_rotate_with_generator(self, manager):
        """Test rotation with generator."""
        manager.set("rotate-me", "old")

        new_secret = manager.rotate("rotate-me", generator=lambda: "generated")
        assert new_secret.value == "generated"

    def test_rotate_nonexistent(self, manager):
        """Test rotating nonexistent secret raises error."""
        with pytest.raises(KeyError):
            manager.rotate("nonexistent")

    def test_rotation_policy(self, manager):
        """Test rotation policy."""
        policy = RotationPolicy(
            name="daily",
            interval=timedelta(days=1),
        )
        manager.set_rotation_policy("daily-secret", policy)

        # Create old secret
        meta = SecretMetadata(
            name="daily-secret",
            created_at=datetime.now() - timedelta(days=2),
        )
        secret = Secret(value="old", metadata=meta)
        manager._backend.set(secret)

        needs_rotation = manager.check_rotation_needed()
        assert "daily-secret" in needs_rotation

    def test_with_encryption(self):
        """Test manager with encryption."""
        encryption = FernetEncryption()
        manager = SecretsManager(encryption=encryption)

        manager.set("encrypted", "sensitive-value", validate=False)

        # Verify stored encrypted
        raw = manager._backend.get("encrypted")
        assert raw.encrypted
        assert raw.value != "sensitive-value"

        # Verify decrypts correctly
        value = manager.get("encrypted")
        assert value == "sensitive-value"

    def test_rotate_encryption_key(self):
        """Test encryption key rotation."""
        encryption = FernetEncryption()
        manager = SecretsManager(encryption=encryption)

        manager.set("secret1", "value1", validate=False)
        manager.set("secret2", "value2", validate=False)

        # Rotate encryption key
        count = manager.rotate_encryption_key()
        assert count == 2

        # Verify secrets still accessible
        assert manager.get("secret1") == "value1"
        assert manager.get("secret2") == "value2"

    def test_access_callback(self, manager):
        """Test access callback."""
        accessed = []
        manager.on_access(lambda name, secret: accessed.append(name))

        manager.set("test", "value")
        manager.get("test")

        assert "test" in accessed

    def test_audit_log(self, manager):
        """Test audit logging."""
        manager.set("audited", "value")
        manager.get("audited")
        manager.delete("audited")

        entries = manager.get_audit_log(secret_name="audited")
        actions = [e["action"] for e in entries]

        assert "set" in actions
        assert "get" in actions
        assert "delete" in actions

    def test_validation_on_set(self, manager):
        """Test validation during set."""
        with pytest.raises(ValueError) as exc:
            manager.set("bad-key", "short", secret_type=SecretType.API_KEY)
        assert "pattern" in str(exc.value).lower()

    def test_skip_validation(self, manager):
        """Test skipping validation."""
        # Should not raise
        manager.set("any-value", "x", secret_type=SecretType.API_KEY, validate=False)

    def test_import_from_env(self, manager):
        """Test importing from environment."""
        with patch.dict(os.environ, {
            "APP_DB_URL": "postgres://...",
            "APP_API_KEY": "sk_test_123",
            "OTHER_VAR": "ignored",
        }):
            count = manager.import_from_env(prefix="APP_")
            assert count == 2
            assert manager.exists("db-url")
            assert manager.exists("api-key")

    def test_export_to_env(self, manager):
        """Test exporting to environment."""
        manager.set("export-me", "value", validate=False)

        count = manager.export_to_env(prefix="TEST_")
        assert count == 1
        assert os.environ.get("TEST_EXPORT_ME") == "value"

        # Cleanup
        del os.environ["TEST_EXPORT_ME"]


# =============================================================================
# Convenience Function Tests
# =============================================================================

class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_create_secrets_manager_memory(self):
        """Test creating memory-backed manager."""
        manager = create_secrets_manager(backend_type="memory")
        manager.set("test", "value", validate=False)
        assert manager.get("test") == "value"

    def test_create_secrets_manager_file(self):
        """Test creating file-backed manager."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name

        try:
            manager = create_secrets_manager(
                backend_type="file",
                path=path,
            )
            manager.set("test", "value", validate=False)
            assert manager.get("test") == "value"
        finally:
            os.unlink(path)

    def test_create_secrets_manager_env(self):
        """Test creating env-backed manager."""
        manager = create_secrets_manager(backend_type="env")
        assert manager is not None

    def test_create_secrets_manager_invalid(self):
        """Test invalid backend type."""
        with pytest.raises(ValueError):
            create_secrets_manager(backend_type="invalid")

    def test_mask_secret(self):
        """Test mask_secret function."""
        assert mask_secret("supersecret", 4) == "supe*******"
        assert mask_secret("abc", 4) == "***"

    def test_generate_password(self):
        """Test generate_password function."""
        pw = generate_password(16)
        assert len(pw) == 16

    def test_generate_api_key(self):
        """Test generate_api_key function."""
        key = generate_api_key(32, "sk")
        assert key.startswith("sk_")

    def test_generate_token(self):
        """Test generate_token function."""
        token = generate_token(64)
        assert len(token) == 64

    def test_hash_secret(self):
        """Test hash_secret function."""
        hashed = hash_secret("mypassword")
        assert "$" in hashed

        # Verify
        assert verify_secret_hash("mypassword", hashed)
        assert not verify_secret_hash("wrongpassword", hashed)

    def test_hash_with_salt(self):
        """Test hash_secret with custom salt."""
        hashed = hash_secret("mypassword", "customsalt")
        assert hashed.startswith("customsalt$")

    def test_verify_invalid_hash(self):
        """Test verify with invalid hash format."""
        assert not verify_secret_hash("value", "not-a-valid-hash")


# =============================================================================
# Integration Tests
# =============================================================================

class TestSecretsManagerIntegration:
    """Integration tests for SecretsManager."""

    def test_full_workflow(self):
        """Test complete secrets workflow."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            secrets_path = f.name
        with tempfile.NamedTemporaryFile(delete=False, mode="w") as f:
            audit_path = f.name

        try:
            # Create manager with file backend and encryption
            manager = create_secrets_manager(
                backend_type="file",
                path=secrets_path,
                audit_path=audit_path,
            )

            # Store secrets
            manager.set(
                "api-key",
                SecretGenerator.api_key(32, "sk"),
                secret_type=SecretType.API_KEY,
                tags={"env": "prod"},
                description="Production API key",
                validate=False,
            )

            manager.set(
                "db-password",
                SecretGenerator.password(16),
                secret_type=SecretType.PASSWORD,
                expires_at=datetime.now() + timedelta(days=90),
                validate=False,
            )

            # Retrieve
            api_key = manager.get("api-key")
            assert api_key.startswith("sk_")

            # Rotate
            manager.rotate("db-password")
            secret = manager.get_secret("db-password")
            assert secret.metadata.version == 2

            # Check audit
            entries = manager.get_audit_log()
            assert len(entries) >= 4  # set, set, get, rotate

        finally:
            os.unlink(secrets_path)
            os.unlink(audit_path)

    def test_multi_threaded_access(self):
        """Test thread-safe access."""
        manager = SecretsManager()
        errors = []

        def worker(worker_id):
            try:
                for i in range(50):
                    name = f"secret-{worker_id}-{i}"
                    manager.set(name, f"value-{i}", validate=False)
                    assert manager.get(name) == f"value-{i}"
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(manager.list()) == 250  # 5 workers * 50 secrets
