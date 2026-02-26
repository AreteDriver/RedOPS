"""Tests for feature flags module."""

import os
import tempfile
import pytest
from datetime import datetime, timedelta

from redops.core.feature_flags import (
    # Exceptions
    FlagNotFoundError,
    FlagConfigurationError,
    # Types
    FlagType,
    FlagState,
    Variant,
    FlagContext,
    # Rules
    AttributeRule,
    UserListRule,
    PercentageRule,
    TimeWindowRule,
    EnvironmentRule,
    CompositeRule,
    # Core
    FeatureFlag,
    MemoryFlagStorage,
    FileFlagStorage,
    # Manager
    FeatureFlagManager,
    # A/B Testing
    Experiment,
    ExperimentManager,
    # Rollout
    GradualRollout,
    # Utilities
    get_default_manager,
    set_default_manager,
    is_enabled,
    get_variant,
    feature_flag,
)


# =============================================================================
# FlagContext Tests
# =============================================================================


class TestFlagContext:
    """Tests for FlagContext."""

    def test_basic_context(self):
        """Test basic context creation."""
        ctx = FlagContext(user_id="user123", environment="staging")
        assert ctx.user_id == "user123"
        assert ctx.environment == "staging"

    def test_attributes(self):
        """Test context attributes."""
        ctx = FlagContext(attributes={"plan": "premium", "country": "US"})
        assert ctx.get("plan") == "premium"
        assert ctx.get("country") == "US"
        assert ctx.get("missing", "default") == "default"

    def test_hash_key(self):
        """Test context hash key generation."""
        ctx1 = FlagContext(user_id="user123")
        ctx2 = FlagContext(user_id="user123")
        ctx3 = FlagContext(user_id="user456")

        # Same user should get same hash
        assert ctx1.hash_key() == ctx2.hash_key()
        # Different user should get different hash
        assert ctx1.hash_key() != ctx3.hash_key()

    def test_hash_key_with_salt(self):
        """Test hash key with salt."""
        ctx = FlagContext(user_id="user123")
        hash1 = ctx.hash_key(salt="salt1")
        hash2 = ctx.hash_key(salt="salt2")
        assert hash1 != hash2


# =============================================================================
# Targeting Rules Tests
# =============================================================================


class TestAttributeRule:
    """Tests for AttributeRule."""

    def test_eq_operator(self):
        """Test equality operator."""
        rule = AttributeRule("plan", "eq", "premium")
        ctx = FlagContext(attributes={"plan": "premium"})
        assert rule.evaluate(ctx) is True

        ctx2 = FlagContext(attributes={"plan": "free"})
        assert rule.evaluate(ctx2) is False

    def test_ne_operator(self):
        """Test not equal operator."""
        rule = AttributeRule("plan", "ne", "premium")
        ctx = FlagContext(attributes={"plan": "free"})
        assert rule.evaluate(ctx) is True

    def test_gt_operator(self):
        """Test greater than operator."""
        rule = AttributeRule("age", "gt", 18)
        ctx = FlagContext(attributes={"age": 25})
        assert rule.evaluate(ctx) is True

        ctx2 = FlagContext(attributes={"age": 18})
        assert rule.evaluate(ctx2) is False

    def test_in_operator(self):
        """Test in operator."""
        rule = AttributeRule("country", "in", ["US", "CA", "UK"])
        ctx = FlagContext(attributes={"country": "US"})
        assert rule.evaluate(ctx) is True

        ctx2 = FlagContext(attributes={"country": "FR"})
        assert rule.evaluate(ctx2) is False

    def test_contains_operator(self):
        """Test contains operator."""
        rule = AttributeRule("email", "contains", "@example.com")
        ctx = FlagContext(attributes={"email": "user@example.com"})
        assert rule.evaluate(ctx) is True

    def test_starts_with_operator(self):
        """Test starts with operator."""
        rule = AttributeRule("user_id", "starts_with", "admin_")
        ctx = FlagContext(user_id="admin_123")
        assert rule.evaluate(ctx) is True

    def test_missing_attribute(self):
        """Test rule with missing attribute."""
        rule = AttributeRule("missing", "eq", "value")
        ctx = FlagContext()
        assert rule.evaluate(ctx) is False

    def test_to_dict(self):
        """Test rule serialization."""
        rule = AttributeRule("plan", "eq", "premium")
        d = rule.to_dict()
        assert d["type"] == "attribute"
        assert d["attribute"] == "plan"


class TestUserListRule:
    """Tests for UserListRule."""

    def test_include_users(self):
        """Test including specific users."""
        rule = UserListRule({"user1", "user2"}, include=True)
        ctx = FlagContext(user_id="user1")
        assert rule.evaluate(ctx) is True

        ctx2 = FlagContext(user_id="user3")
        assert rule.evaluate(ctx2) is False

    def test_exclude_users(self):
        """Test excluding specific users."""
        rule = UserListRule({"user1", "user2"}, include=False)
        ctx = FlagContext(user_id="user3")
        assert rule.evaluate(ctx) is True

        ctx2 = FlagContext(user_id="user1")
        assert rule.evaluate(ctx2) is False

    def test_no_user_id(self):
        """Test with no user ID in context."""
        rule = UserListRule({"user1"}, include=True)
        ctx = FlagContext()
        assert rule.evaluate(ctx) is False


class TestPercentageRule:
    """Tests for PercentageRule."""

    def test_percentage_distribution(self):
        """Test percentage-based distribution."""
        rule = PercentageRule(50.0, salt="test")

        # With enough samples, roughly 50% should pass
        passes = 0
        total = 1000
        for i in range(total):
            ctx = FlagContext(user_id=f"user_{i}")
            if rule.evaluate(ctx):
                passes += 1

        # Allow some variance
        assert 400 < passes < 600

    def test_zero_percentage(self):
        """Test 0% always fails."""
        rule = PercentageRule(0.0)
        for i in range(100):
            ctx = FlagContext(user_id=f"user_{i}")
            assert rule.evaluate(ctx) is False

    def test_hundred_percentage(self):
        """Test 100% always passes."""
        rule = PercentageRule(100.0)
        for i in range(100):
            ctx = FlagContext(user_id=f"user_{i}")
            assert rule.evaluate(ctx) is True

    def test_consistency(self):
        """Test same user always gets same result."""
        rule = PercentageRule(50.0, salt="test")
        ctx = FlagContext(user_id="user123")
        result = rule.evaluate(ctx)

        # Same result every time
        for _ in range(10):
            assert rule.evaluate(ctx) == result

    def test_invalid_percentage(self):
        """Test invalid percentage raises error."""
        with pytest.raises(FlagConfigurationError):
            PercentageRule(150.0)


class TestTimeWindowRule:
    """Tests for TimeWindowRule."""

    def test_within_window(self):
        """Test evaluation within time window."""
        now = datetime.now()
        rule = TimeWindowRule(
            start_time=now - timedelta(hours=1), end_time=now + timedelta(hours=1)
        )
        ctx = FlagContext(timestamp=now)
        assert rule.evaluate(ctx) is True

    def test_before_window(self):
        """Test evaluation before time window."""
        now = datetime.now()
        rule = TimeWindowRule(start_time=now + timedelta(hours=1))
        ctx = FlagContext(timestamp=now)
        assert rule.evaluate(ctx) is False

    def test_after_window(self):
        """Test evaluation after time window."""
        now = datetime.now()
        rule = TimeWindowRule(end_time=now - timedelta(hours=1))
        ctx = FlagContext(timestamp=now)
        assert rule.evaluate(ctx) is False


class TestEnvironmentRule:
    """Tests for EnvironmentRule."""

    def test_matching_environment(self):
        """Test matching environment."""
        rule = EnvironmentRule({"staging", "production"})
        ctx = FlagContext(environment="staging")
        assert rule.evaluate(ctx) is True

    def test_non_matching_environment(self):
        """Test non-matching environment."""
        rule = EnvironmentRule({"production"})
        ctx = FlagContext(environment="staging")
        assert rule.evaluate(ctx) is False


class TestCompositeRule:
    """Tests for CompositeRule."""

    def test_and_operator(self):
        """Test AND operator."""
        rule = CompositeRule(
            [
                AttributeRule("plan", "eq", "premium"),
                AttributeRule("verified", "eq", True),
            ],
            operator="and",
        )

        ctx = FlagContext(attributes={"plan": "premium", "verified": True})
        assert rule.evaluate(ctx) is True

        ctx2 = FlagContext(attributes={"plan": "premium", "verified": False})
        assert rule.evaluate(ctx2) is False

    def test_or_operator(self):
        """Test OR operator."""
        rule = CompositeRule(
            [
                AttributeRule("plan", "eq", "premium"),
                AttributeRule("plan", "eq", "enterprise"),
            ],
            operator="or",
        )

        ctx = FlagContext(attributes={"plan": "premium"})
        assert rule.evaluate(ctx) is True

        ctx2 = FlagContext(attributes={"plan": "free"})
        assert rule.evaluate(ctx2) is False

    def test_not_operator(self):
        """Test NOT operator."""
        rule = CompositeRule([AttributeRule("banned", "eq", True)], operator="not")

        ctx = FlagContext(attributes={"banned": False})
        assert rule.evaluate(ctx) is True


# =============================================================================
# FeatureFlag Tests
# =============================================================================


class TestFeatureFlag:
    """Tests for FeatureFlag."""

    def test_disabled_flag(self):
        """Test disabled flag returns default."""
        flag = FeatureFlag(key="test", state=FlagState.DISABLED, default_value=False)
        assert flag.evaluate() is False

    def test_enabled_boolean_flag(self):
        """Test enabled boolean flag."""
        flag = FeatureFlag(
            key="test", flag_type=FlagType.BOOLEAN, state=FlagState.ENABLED
        )
        assert flag.evaluate() is True

    def test_conditional_flag(self):
        """Test conditional flag with rules."""
        flag = FeatureFlag(key="test", default_value=False)
        flag.add_rule(AttributeRule("plan", "eq", "premium"), True)

        ctx_premium = FlagContext(attributes={"plan": "premium"})
        ctx_free = FlagContext(attributes={"plan": "free"})

        assert flag.evaluate(ctx_premium) is True
        assert flag.evaluate(ctx_free) is False

    def test_variant_selection(self):
        """Test variant selection."""
        flag = FeatureFlag(key="test", state=FlagState.ENABLED)
        flag.add_variant("control", "A", weight=1)
        flag.add_variant("treatment", "B", weight=1)

        # Different users should get consistent variants
        results = {}
        for i in range(100):
            ctx = FlagContext(user_id=f"user_{i}")
            value = flag.evaluate(ctx)
            results[value] = results.get(value, 0) + 1

        # Both variants should be selected
        assert len(results) == 2
        assert "A" in results
        assert "B" in results

    def test_is_enabled(self):
        """Test is_enabled method."""
        flag = FeatureFlag(key="test", state=FlagState.ENABLED)
        assert flag.is_enabled() is True

        flag.disable()
        assert flag.is_enabled() is False

    def test_enable_disable(self):
        """Test enable/disable methods."""
        flag = FeatureFlag(key="test", state=FlagState.DISABLED)
        assert flag.state == FlagState.DISABLED

        flag.enable()
        assert flag.state == FlagState.ENABLED

        flag.disable()
        assert flag.state == FlagState.DISABLED

    def test_to_dict(self):
        """Test flag serialization."""
        flag = FeatureFlag(
            key="test", flag_type=FlagType.BOOLEAN, description="Test flag"
        )
        d = flag.to_dict()
        assert d["key"] == "test"
        assert d["flag_type"] == "boolean"
        assert d["description"] == "Test flag"


# =============================================================================
# Flag Storage Tests
# =============================================================================


class TestMemoryFlagStorage:
    """Tests for MemoryFlagStorage."""

    def test_set_and_get(self):
        """Test storing and retrieving flags."""
        storage = MemoryFlagStorage()
        flag = FeatureFlag(key="test")
        storage.set(flag)

        retrieved = storage.get("test")
        assert retrieved is not None
        assert retrieved.key == "test"

    def test_get_nonexistent(self):
        """Test getting nonexistent flag."""
        storage = MemoryFlagStorage()
        assert storage.get("nonexistent") is None

    def test_delete(self):
        """Test deleting a flag."""
        storage = MemoryFlagStorage()
        flag = FeatureFlag(key="test")
        storage.set(flag)

        assert storage.delete("test") is True
        assert storage.get("test") is None
        assert storage.delete("test") is False

    def test_list_all(self):
        """Test listing all flags."""
        storage = MemoryFlagStorage()
        storage.set(FeatureFlag(key="flag1"))
        storage.set(FeatureFlag(key="flag2"))

        flags = storage.list_all()
        assert len(flags) == 2
        keys = {f.key for f in flags}
        assert keys == {"flag1", "flag2"}


class TestFileFlagStorage:
    """Tests for FileFlagStorage."""

    def test_file_persistence(self):
        """Test file persistence."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{}")
            file_path = f.name

        try:
            storage1 = FileFlagStorage(file_path)
            flag = FeatureFlag(key="test", description="Test flag")
            storage1.set(flag)

            # Create new storage instance
            storage2 = FileFlagStorage(file_path)
            retrieved = storage2.get("test")
            assert retrieved is not None
            assert retrieved.key == "test"
        finally:
            os.unlink(file_path)

    def test_missing_file(self):
        """Test handling missing file."""
        storage = FileFlagStorage("/nonexistent/path/flags.json")
        assert storage.list_all() == []


# =============================================================================
# FeatureFlagManager Tests
# =============================================================================


class TestFeatureFlagManager:
    """Tests for FeatureFlagManager."""

    def test_create_flag(self):
        """Test creating a flag."""
        manager = FeatureFlagManager()
        flag = manager.create_flag("test_feature")

        assert flag.key == "test_feature"
        assert manager.get_flag("test_feature") is not None

    def test_evaluate(self):
        """Test flag evaluation."""
        manager = FeatureFlagManager()
        manager.create_flag("test_feature", default_value=False)

        flag = manager.get_flag("test_feature")
        flag.enable()
        manager.update_flag(flag)

        assert manager.evaluate("test_feature") is True

    def test_evaluate_not_found(self):
        """Test evaluating nonexistent flag."""
        manager = FeatureFlagManager()
        with pytest.raises(FlagNotFoundError):
            manager.evaluate("nonexistent")

    def test_evaluate_with_default(self):
        """Test evaluation with default value."""
        manager = FeatureFlagManager()
        result = manager.evaluate("nonexistent", default="fallback")
        assert result == "fallback"

    def test_is_enabled(self):
        """Test is_enabled method."""
        manager = FeatureFlagManager()
        flag = manager.create_flag("test_feature")
        flag.enable()
        manager.update_flag(flag)

        assert manager.is_enabled("test_feature") is True
        assert manager.is_enabled("nonexistent", default=False) is False

    def test_override(self):
        """Test flag override."""
        manager = FeatureFlagManager()
        flag = manager.create_flag("test_feature", default_value=False)
        flag.enable()
        manager.update_flag(flag)

        # Set override
        manager.set_override("test_feature", False)
        assert manager.evaluate("test_feature") is False

        # Clear override
        manager.clear_override("test_feature")
        assert manager.evaluate("test_feature") is True

    def test_clear_all_overrides(self):
        """Test clearing all overrides."""
        manager = FeatureFlagManager()
        manager.create_flag("flag1")
        manager.create_flag("flag2")

        manager.set_override("flag1", True)
        manager.set_override("flag2", True)
        manager.clear_all_overrides()

        # Should not find flag in overrides
        assert manager.evaluate("flag1", default=False) is False

    def test_listener(self):
        """Test evaluation listener."""
        manager = FeatureFlagManager()
        flag = manager.create_flag("test_feature")
        flag.enable()
        manager.update_flag(flag)

        evaluations = []

        def listener(key, value, context):
            evaluations.append((key, value))

        manager.add_listener(listener)
        manager.evaluate("test_feature")

        assert len(evaluations) == 1
        assert evaluations[0][0] == "test_feature"

    def test_evaluation_history(self):
        """Test evaluation history."""
        manager = FeatureFlagManager()
        flag = manager.create_flag("test_feature")
        flag.enable()
        manager.update_flag(flag)

        for _ in range(5):
            manager.evaluate("test_feature")

        history = manager.get_evaluation_history()
        assert len(history) == 5
        assert all(h.flag_key == "test_feature" for h in history)

    def test_flag_stats(self):
        """Test flag statistics."""
        manager = FeatureFlagManager()
        flag = manager.create_flag("test_feature")
        flag.enable()
        manager.update_flag(flag)

        for i in range(10):
            ctx = FlagContext(user_id=f"user_{i}")
            manager.evaluate("test_feature", ctx)

        stats = manager.get_flag_stats("test_feature")
        assert stats["total"] == 10
        assert stats["unique_contexts"] == 10

    def test_list_flags_by_tags(self):
        """Test listing flags by tags."""
        manager = FeatureFlagManager()
        manager.create_flag("flag1", tags={"frontend", "experiment"})
        manager.create_flag("flag2", tags={"backend"})
        manager.create_flag("flag3", tags={"frontend", "release"})

        frontend_flags = manager.list_flags(tags={"frontend"})
        assert len(frontend_flags) == 2


# =============================================================================
# Experiment Tests
# =============================================================================


class TestExperiment:
    """Tests for Experiment."""

    def test_running_experiment(self):
        """Test running experiment."""
        exp = Experiment(
            name="test_exp",
            is_active=True,
            variants=[Variant("control", "A"), Variant("treatment", "B")],
        )
        assert exp.is_running() is True

    def test_not_running_inactive(self):
        """Test inactive experiment not running."""
        exp = Experiment(name="test_exp", is_active=False)
        assert exp.is_running() is False

    def test_not_running_before_start(self):
        """Test experiment before start time."""
        exp = Experiment(
            name="test_exp",
            is_active=True,
            start_time=datetime.now() + timedelta(hours=1),
        )
        assert exp.is_running() is False

    def test_not_running_after_end(self):
        """Test experiment after end time."""
        exp = Experiment(
            name="test_exp",
            is_active=True,
            end_time=datetime.now() - timedelta(hours=1),
        )
        assert exp.is_running() is False

    def test_get_variant(self):
        """Test variant selection."""
        exp = Experiment(
            name="test_exp",
            is_active=True,
            variants=[
                Variant("control", "A", weight=1),
                Variant("treatment", "B", weight=1),
            ],
        )

        ctx = FlagContext(user_id="user123")
        variant = exp.get_variant(ctx)
        assert variant is not None
        assert variant.value in ["A", "B"]

    def test_variant_consistency(self):
        """Test variant assignment consistency."""
        exp = Experiment(
            name="test_exp",
            is_active=True,
            variants=[Variant("control", "A"), Variant("treatment", "B")],
        )

        ctx = FlagContext(user_id="user123")
        variant1 = exp.get_variant(ctx)
        variant2 = exp.get_variant(ctx)
        assert variant1.value == variant2.value


class TestExperimentManager:
    """Tests for ExperimentManager."""

    def test_create_experiment(self):
        """Test creating an experiment."""
        manager = ExperimentManager()
        exp = manager.create_experiment(
            "test_exp", variants=[Variant("A", 1), Variant("B", 2)]
        )
        assert exp.name == "test_exp"

    def test_start_stop_experiment(self):
        """Test starting and stopping experiment."""
        manager = ExperimentManager()
        manager.create_experiment("test_exp", variants=[Variant("A", 1)])

        assert manager.start_experiment("test_exp") is True
        exp = manager.get_experiment("test_exp")
        assert exp.is_active is True

        assert manager.stop_experiment("test_exp") is True
        assert exp.is_active is False

    def test_get_variant(self):
        """Test getting variant through manager."""
        manager = ExperimentManager()
        manager.create_experiment(
            "test_exp", variants=[Variant("control", "A"), Variant("treatment", "B")]
        )
        manager.start_experiment("test_exp")

        ctx = FlagContext(user_id="user123")
        variant = manager.get_variant("test_exp", ctx)
        assert variant is not None

    def test_persistent_assignment(self):
        """Test persistent variant assignment."""
        manager = ExperimentManager()
        manager.create_experiment(
            "test_exp", variants=[Variant("A", 1), Variant("B", 2)]
        )
        manager.start_experiment("test_exp")

        ctx = FlagContext(user_id="user123")
        variant1 = manager.get_variant("test_exp", ctx)
        variant2 = manager.get_variant("test_exp", ctx)

        assert variant1.name == variant2.name

    def test_list_experiments(self):
        """Test listing experiments."""
        manager = ExperimentManager()
        manager.create_experiment("exp1", variants=[Variant("A", 1)])
        manager.create_experiment("exp2", variants=[Variant("B", 1)])
        manager.start_experiment("exp1")

        all_exps = manager.list_experiments()
        assert len(all_exps) == 2

        active_exps = manager.list_experiments(active_only=True)
        assert len(active_exps) == 1


# =============================================================================
# GradualRollout Tests
# =============================================================================


class TestGradualRollout:
    """Tests for GradualRollout."""

    def test_add_stages(self):
        """Test adding rollout stages."""
        manager = FeatureFlagManager()
        manager.create_flag("new_feature")

        rollout = GradualRollout("new_feature", manager)
        rollout.add_stage(10, "beta")
        rollout.add_stage(50, "early_access")
        rollout.add_stage(100, "general_availability")

        assert len(rollout.stages) == 3

    def test_invalid_stage_order(self):
        """Test invalid stage order."""
        manager = FeatureFlagManager()
        manager.create_flag("new_feature")

        rollout = GradualRollout("new_feature", manager)
        rollout.add_stage(50)

        with pytest.raises(FlagConfigurationError):
            rollout.add_stage(30)  # Must be increasing

    def test_advance_rollout(self):
        """Test advancing rollout."""
        manager = FeatureFlagManager()
        manager.create_flag("new_feature")

        rollout = GradualRollout("new_feature", manager)
        rollout.add_stage(10)
        rollout.add_stage(50)
        rollout.add_stage(100)

        assert rollout.get_current_percentage() == 0.0

        rollout.advance()
        assert rollout.get_current_percentage() == 10.0

        rollout.advance()
        assert rollout.get_current_percentage() == 50.0

    def test_rollback(self):
        """Test rollback."""
        manager = FeatureFlagManager()
        manager.create_flag("new_feature")

        rollout = GradualRollout("new_feature", manager)
        rollout.add_stage(10)
        rollout.add_stage(50)

        rollout.advance()
        rollout.advance()
        assert rollout.get_current_percentage() == 50.0

        rollout.rollback()
        assert rollout.get_current_percentage() == 10.0

    def test_complete_rollout(self):
        """Test completing rollout."""
        manager = FeatureFlagManager()
        manager.create_flag("new_feature")

        rollout = GradualRollout("new_feature", manager)
        rollout.add_stage(50)
        rollout.advance()
        rollout.complete()

        flag = manager.get_flag("new_feature")
        assert flag.state == FlagState.ENABLED

    def test_get_status(self):
        """Test getting rollout status."""
        manager = FeatureFlagManager()
        manager.create_flag("new_feature")

        rollout = GradualRollout("new_feature", manager)
        rollout.add_stage(10, "beta")
        rollout.add_stage(100, "ga")
        rollout.advance()

        status = rollout.get_status()
        assert status["flag_key"] == "new_feature"
        assert status["current_percentage"] == 10.0
        assert len(status["stages"]) == 2


# =============================================================================
# Global Utility Tests
# =============================================================================


class TestGlobalUtilities:
    """Tests for global utility functions."""

    def test_default_manager(self):
        """Test default manager."""
        manager = get_default_manager()
        assert manager is not None

    def test_set_default_manager(self):
        """Test setting default manager."""
        custom_manager = FeatureFlagManager()
        set_default_manager(custom_manager)

        assert get_default_manager() is custom_manager

    def test_is_enabled_function(self):
        """Test is_enabled utility function."""
        manager = FeatureFlagManager()
        flag = manager.create_flag("test_feature")
        flag.enable()
        manager.update_flag(flag)
        set_default_manager(manager)

        assert is_enabled("test_feature") is True
        assert is_enabled("nonexistent", default=False) is False

    def test_get_variant_function(self):
        """Test get_variant utility function."""
        manager = FeatureFlagManager()
        flag = manager.create_flag("test_feature", flag_type=FlagType.STRING)
        flag.add_variant("A", "value_a")
        flag.enable()
        manager.update_flag(flag)
        set_default_manager(manager)

        result = get_variant("test_feature")
        assert result == "value_a"

    def test_feature_flag_decorator(self):
        """Test feature_flag decorator."""
        manager = FeatureFlagManager()
        flag = manager.create_flag("test_feature")
        flag.enable()
        manager.update_flag(flag)
        set_default_manager(manager)

        @feature_flag("test_feature")
        def enabled_function():
            return "executed"

        @feature_flag("disabled_feature", default=False)
        def disabled_function():
            return "executed"

        assert enabled_function() == "executed"
        assert disabled_function() is None


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests."""

    def test_full_flag_workflow(self):
        """Test complete flag workflow."""
        manager = FeatureFlagManager()

        # Create flag
        flag = manager.create_flag(
            "premium_feature",
            flag_type=FlagType.BOOLEAN,
            default_value=False,
            description="Premium-only feature",
        )

        # Add targeting rules
        flag.add_rule(AttributeRule("plan", "eq", "premium"), True)
        manager.update_flag(flag)

        # Test evaluation
        free_user = FlagContext(attributes={"plan": "free"})
        premium_user = FlagContext(attributes={"plan": "premium"})

        assert manager.evaluate("premium_feature", free_user) is False
        assert manager.evaluate("premium_feature", premium_user) is True

    def test_gradual_rollout_with_monitoring(self):
        """Test gradual rollout with monitoring."""
        manager = FeatureFlagManager()
        manager.create_flag("new_feature")

        rollout = GradualRollout("new_feature", manager)
        rollout.add_stage(10, "beta")
        rollout.add_stage(50, "early_access")
        rollout.add_stage(100, "ga")

        # Start rollout
        rollout.advance()

        # Simulate users - use 1000 samples to reduce statistical variance
        # (GradualRollout salt includes time.time(), so hash distribution
        # varies per run; larger sample size keeps assertions reliable)
        total = 1000
        enabled_count = 0
        for i in range(total):
            ctx = FlagContext(user_id=f"user_{i}")
            if manager.is_enabled("new_feature", ctx):
                enabled_count += 1

        # Should be around 10% (expect 100, stddev ~9.5, bounds at ~5 sigma)
        assert 50 <= enabled_count <= 150

        # Advance to 50%
        rollout.advance()
        enabled_count = 0
        for i in range(total):
            ctx = FlagContext(user_id=f"user_{i}")
            if manager.is_enabled("new_feature", ctx):
                enabled_count += 1

        # Should be around 50% (expect 500, stddev ~15.8, bounds at ~5 sigma)
        assert 420 <= enabled_count <= 580

    def test_complex_targeting(self):
        """Test complex targeting rules."""
        manager = FeatureFlagManager()
        flag = manager.create_flag("complex_feature")

        # Premium users OR beta testers AND not banned
        targeting = CompositeRule(
            [
                CompositeRule(
                    [
                        AttributeRule("plan", "eq", "premium"),
                        UserListRule({"beta_user_1", "beta_user_2"}),
                    ],
                    operator="or",
                ),
                CompositeRule([AttributeRule("banned", "eq", True)], operator="not"),
            ],
            operator="and",
        )

        flag.add_rule(targeting, True)
        manager.update_flag(flag)

        # Premium non-banned user
        ctx1 = FlagContext(attributes={"plan": "premium", "banned": False})
        assert manager.evaluate("complex_feature", ctx1) is True

        # Beta tester
        ctx2 = FlagContext(
            user_id="beta_user_1", attributes={"plan": "free", "banned": False}
        )
        assert manager.evaluate("complex_feature", ctx2) is True

        # Premium but banned
        ctx3 = FlagContext(attributes={"plan": "premium", "banned": True})
        assert manager.evaluate("complex_feature", ctx3) is False

        # Free non-beta user
        ctx4 = FlagContext(
            user_id="regular_user", attributes={"plan": "free", "banned": False}
        )
        assert manager.evaluate("complex_feature", ctx4) is False
