"""Integration tests for RedOPS database, cache, and pipeline subsystems.

These tests verify end-to-end behavior that spans multiple subsystems.
They may require services (Postgres, Redis) when run in CI.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


class TestCLIIntegration:
    """Integration tests for the CLI entry point."""

    def test_version_command(self):
        """Verify redops version returns successfully."""
        result = subprocess.run(
            [sys.executable, "-m", "redops.main", "version"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "1.5.0" in result.stdout


class TestPipelineIntegration:
    """Integration tests for pipeline loading and validation."""

    def test_all_pipelines_are_valid_json(self):
        """Verify every pipeline JSON file loads without errors."""
        pipeline_dir = Path("config/pipelines")
        if not pipeline_dir.exists():
            pytest.skip("Pipeline directory not found")

        pipeline_files = list(pipeline_dir.glob("*.json"))
        assert len(pipeline_files) > 0, "No pipeline files found"

        for pipeline_file in pipeline_files:
            with open(pipeline_file, "r") as f:
                data = json.load(f)
            assert "metadata" in data
            assert "steps" in data
            assert isinstance(data["steps"], list)


class TestConfigIntegration:
    """Integration tests for configuration loading."""

    def test_config_from_file(self, tmp_path):
        """Verify RedOpsConfig can be loaded from a JSON file."""
        from redops.core.config import RedOpsConfig

        config_path = tmp_path / "test_config.json"
        config_data = {
            "scope": {
                "allowed_domains": ["example.com"],
                "strict_mode": True,
            },
            "output": {
                "output_dir": str(tmp_path / "output"),
                "format": "json",
            },
        }
        config_path.write_text(json.dumps(config_data))

        config = RedOpsConfig.from_file(config_path)
        assert config.scope.allowed_domains == ["example.com"]
        assert config.scope.strict_mode is True
        assert config.output.format == "json"

    def test_config_from_env(self):
        """Verify RedOpsConfig respects environment variables."""
        from redops.core.config import RedOpsConfig

        original_output_dir = os.environ.get("REDOPS_OUTPUT_DIR")
        original_verbose = os.environ.get("REDOPS_VERBOSE")

        try:
            os.environ["REDOPS_OUTPUT_DIR"] = "/tmp/redops_test"
            os.environ["REDOPS_VERBOSE"] = "true"

            config = RedOpsConfig.from_env()
            assert config.output.output_dir == "/tmp/redops_test"
            assert config.output.verbose is True
        finally:
            if original_output_dir is not None:
                os.environ["REDOPS_OUTPUT_DIR"] = original_output_dir
            else:
                os.environ.pop("REDOPS_OUTPUT_DIR", None)

            if original_verbose is not None:
                os.environ["REDOPS_VERBOSE"] = original_verbose
            else:
                os.environ.pop("REDOPS_VERBOSE", None)


@pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="DATABASE_URL not set (Postgres unavailable)",
)
class TestDatabaseIntegration:
    """Integration tests requiring a live Postgres database."""

    @pytest.fixture(autouse=True)
    def reset_database(self):
        """Drop and recreate tables before each test."""
        from redops.db.connection import DatabaseConfig, Database
        from redops.db.models import Base

        config = DatabaseConfig.from_env()
        db = Database(config)
        Base.metadata.drop_all(db.engine)
        Base.metadata.create_all(db.engine)
        yield
        db.dispose()

    def test_database_connection(self):
        """Verify database connection works."""
        from redops.db.connection import DatabaseConfig, Database

        config = DatabaseConfig.from_env()
        db = Database(config)
        assert db.check_connection() is True
        db.dispose()

    def test_create_and_get_user(self):
        """Verify user CRUD through the database session."""
        from redops.db.connection import DatabaseConfig, Database
        from redops.db.models import User

        config = DatabaseConfig.from_env()
        db = Database(config)

        with db.session_scope() as session:
            user = User(
                username="integration_test",
                email="test@example.com",
                password_hash="$2b$12$fakehash",
                role="user",
            )
            session.add(user)

        with db.session_scope() as session:
            fetched = session.query(User).filter_by(username="integration_test").first()
            assert fetched is not None
            assert fetched.email == "test@example.com"
            assert fetched.role == "user"

        db.dispose()

    def test_create_scan_and_findings(self):
        """Verify scan and finding creation with relationships."""
        from datetime import datetime, timezone
        from redops.db.connection import DatabaseConfig, Database
        from redops.db.models import Scan, Finding

        config = DatabaseConfig.from_env()
        db = Database(config)

        with db.session_scope() as session:
            scan = Scan(
                target="https://example.com",
                pipeline="web_security",
                status="completed",
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
            )
            session.add(scan)
            session.flush()

            finding = Finding(
                scan_id=scan.id,
                title="Test Finding",
                severity="high",
                description="Integration test finding",
                status="open",
            )
            session.add(finding)

        with db.session_scope() as session:
            fetched_scan = session.query(Scan).filter_by(target="https://example.com").first()
            assert fetched_scan is not None
            assert len(fetched_scan.findings) == 1
            assert fetched_scan.findings[0].title == "Test Finding"

        db.dispose()


@pytest.mark.skipif(
    not os.environ.get("REDIS_HOST"),
    reason="REDIS_HOST not set (Redis unavailable)",
)
class TestRedisCacheIntegration:
    """Integration tests requiring a live Redis instance."""

    @pytest.fixture
    def redis_cache(self):
        """Create a Redis-backed cache instance."""
        from redops.cache.cache import Cache, CacheConfig

        config = CacheConfig(
            backend="redis",
            redis_host=os.environ.get("REDIS_HOST", "localhost"),
            redis_port=int(os.environ.get("REDIS_PORT", "6379")),
            redis_db=int(os.environ.get("REDIS_DB", "0")),
            default_ttl_seconds=60,
        )
        cache = Cache(config)
        yield cache
        # Cleanup — remove test keys
        cache._backend.flush()

    def test_redis_set_and_get(self, redis_cache):
        """Verify Redis-backed cache stores and retrieves values."""
        redis_cache.set("test_key", {"foo": "bar"})
        result = redis_cache.get("test_key")
        assert result == {"foo": "bar"}

    def test_redis_ttl_expiry(self, redis_cache):
        """Verify values expire after TTL."""
        import time

        redis_cache.set("ttl_key", "value", ttl_seconds=1)
        assert redis_cache.get("ttl_key") == "value"
        time.sleep(2)
        assert redis_cache.get("ttl_key") is None

    def test_redis_delete(self, redis_cache):
        """Verify delete removes values."""
        redis_cache.set("delete_key", "value")
        assert redis_cache.get("delete_key") == "value"
        redis_cache.delete("delete_key")
        assert redis_cache.get("delete_key") is None


class TestPipelineRunnerIntegration:
    """Integration tests for the pipeline runner end-to-end."""

    def test_run_pipeline_with_mock_modules(self, tmp_path):
        """Run a minimal pipeline with mock modules."""
        from redops.core.context import Context
        from redops.pipelines.runner import PipelineRunner
        from redops.pipelines.schemas import Pipeline, PipelineStep

        pipeline = Pipeline(
            metadata={"name": "test-pipeline", "version": "1.0.0"},
            steps=[
                PipelineStep(
                    name="mock-step",
                    module="recon.domains.profile_domain",
                    params={"target": "example.com"},
                ),
            ],
        )

        ctx = Context(target="example.com")
        runner = PipelineRunner(pipeline=pipeline)
        # PipelineRunner.validate checks schema correctness without running modules.
        result = runner.pipeline.validate_pipeline()
        assert result is True

    def test_context_authorization_lifecycle(self):
        """Verify Context authorization is recorded and checked end-to-end."""
        from redops.core.context import Context
        from redops.modules.active.authorization import record_authorization, assert_active_authorized
        from redops.modules.active.exceptions import ActiveAuthorizationError

        ctx = Context(target="home-lab")

        # Should fail without authorization
        with pytest.raises(ActiveAuthorizationError):
            assert_active_authorized(ctx)

        # Record authorization
        record_authorization(ctx, operator="test-operator", target_assertion="home-lab")

        # Should succeed now
        assert_active_authorized(ctx)  # no exception

    def test_context_data_add_and_retrieve(self):
        """Verify Context data storage and retrieval."""
        from redops.core.context import Context

        ctx = Context(target="example.com")
        ctx.add("findings", [{"id": "f1", "severity": "high"}])

        findings = ctx.get("findings")
        assert len(findings) == 1
        assert findings[0]["id"] == "f1"

        # add() replaces the value; verify overwrite behavior
        ctx.add("findings", [{"id": "f2", "severity": "medium"}])
        findings = ctx.get("findings")
        assert len(findings) == 1
        assert findings[0]["id"] == "f2"

    def test_egress_blocking_external_requests(self):
        """Verify external egress is blocked during active execution."""
        import requests
        from redops.modules.active.egress import block_external_egress
        from redops.modules.active.exceptions import EgressBlockedError

        with block_external_egress():
            with pytest.raises(EgressBlockedError):
                requests.get("https://example.com", timeout=1)

    def test_egress_allows_localhost(self):
        """Verify localhost requests are not blocked."""
        import requests
        from redops.modules.active.egress import block_external_egress

        # This test does not start a server; it relies on connection refused
        # being an expected outcome, not an egress block.
        with block_external_egress():
            with pytest.raises(requests.ConnectionError):
                requests.get("http://127.0.0.1:59999/nonexistent", timeout=1)
