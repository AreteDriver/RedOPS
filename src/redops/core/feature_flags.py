"""Feature flags module for RedOPS.

Provides feature toggles, A/B testing, gradual rollouts, and flag management.
"""

import hashlib
import json
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable


class FlagNotFoundError(Exception):
    """Raised when a feature flag is not found."""

    pass


class FlagConfigurationError(Exception):
    """Raised when flag configuration is invalid."""

    pass


# =============================================================================
# Flag Types and Variants
# =============================================================================


class FlagType(Enum):
    """Types of feature flags."""

    BOOLEAN = "boolean"  # Simple on/off
    STRING = "string"  # String variant
    NUMBER = "number"  # Numeric value
    JSON = "json"  # JSON object
    PERCENTAGE = "percentage"  # Percentage-based rollout


class FlagState(Enum):
    """State of a feature flag."""

    ENABLED = "enabled"
    DISABLED = "disabled"
    CONDITIONAL = "conditional"


@dataclass
class Variant:
    """A variant for multi-variant flags."""

    name: str
    value: Any
    weight: int = 1  # Weight for weighted distribution
    description: str = ""


@dataclass
class FlagContext:
    """Context for flag evaluation."""

    user_id: str | None = None
    session_id: str | None = None
    environment: str = "production"
    attributes: dict[str, Any] = field(default_factory=dict)
    ip_address: str | None = None
    user_agent: str | None = None
    timestamp: datetime = field(default_factory=datetime.now)

    def get(self, key: str, default: Any = None) -> Any:
        """Get an attribute value."""
        return self.attributes.get(key, default)

    def hash_key(self, salt: str = "") -> str:
        """Generate a consistent hash key for this context."""
        key_parts = [self.user_id or "", self.session_id or "", salt]
        key_string = ":".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()


# =============================================================================
# Targeting Rules
# =============================================================================


class TargetingRule(ABC):
    """Base class for targeting rules."""

    @abstractmethod
    def evaluate(self, context: FlagContext) -> bool:
        """Evaluate the rule against the context."""
        pass

    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        """Serialize the rule to a dictionary."""
        pass


class AttributeRule(TargetingRule):
    """Rule based on context attributes."""

    def __init__(self, attribute: str, operator: str, value: Any):
        self.attribute = attribute
        self.operator = operator
        self.value = value

    def evaluate(self, context: FlagContext) -> bool:
        ctx_value = context.get(self.attribute)
        if ctx_value is None:
            # Check direct context attributes
            ctx_value = getattr(context, self.attribute, None)

        if ctx_value is None:
            return False

        if self.operator == "eq":
            return ctx_value == self.value
        elif self.operator == "ne":
            return ctx_value != self.value
        elif self.operator == "gt":
            return ctx_value > self.value
        elif self.operator == "gte":
            return ctx_value >= self.value
        elif self.operator == "lt":
            return ctx_value < self.value
        elif self.operator == "lte":
            return ctx_value <= self.value
        elif self.operator == "in":
            return ctx_value in self.value
        elif self.operator == "not_in":
            return ctx_value not in self.value
        elif self.operator == "contains":
            return self.value in ctx_value
        elif self.operator == "starts_with":
            return str(ctx_value).startswith(str(self.value))
        elif self.operator == "ends_with":
            return str(ctx_value).endswith(str(self.value))
        elif self.operator == "matches":
            import re

            return bool(re.match(self.value, str(ctx_value)))
        else:
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "attribute",
            "attribute": self.attribute,
            "operator": self.operator,
            "value": self.value,
        }


class UserListRule(TargetingRule):
    """Rule targeting specific users."""

    def __init__(self, user_ids: set[str], include: bool = True):
        self.user_ids = user_ids
        self.include = include

    def evaluate(self, context: FlagContext) -> bool:
        if not context.user_id:
            return not self.include
        in_list = context.user_id in self.user_ids
        return in_list if self.include else not in_list

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "user_list",
            "user_ids": list(self.user_ids),
            "include": self.include,
        }


class PercentageRule(TargetingRule):
    """Rule for percentage-based rollout."""

    def __init__(self, percentage: float, salt: str = ""):
        if not 0 <= percentage <= 100:
            raise FlagConfigurationError("Percentage must be between 0 and 100")
        self.percentage = percentage
        self.salt = salt

    def evaluate(self, context: FlagContext) -> bool:
        hash_key = context.hash_key(self.salt)
        # Convert first 8 hex chars to number and mod 100
        bucket = int(hash_key[:8], 16) % 100
        return bucket < self.percentage

    def to_dict(self) -> dict[str, Any]:
        return {"type": "percentage", "percentage": self.percentage, "salt": self.salt}


class TimeWindowRule(TargetingRule):
    """Rule based on time window."""

    def __init__(
        self, start_time: datetime | None = None, end_time: datetime | None = None
    ):
        self.start_time = start_time
        self.end_time = end_time

    def evaluate(self, context: FlagContext) -> bool:
        now = context.timestamp
        if self.start_time and now < self.start_time:
            return False
        if self.end_time and now > self.end_time:
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "time_window",
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
        }


class EnvironmentRule(TargetingRule):
    """Rule based on environment."""

    def __init__(self, environments: set[str]):
        self.environments = environments

    def evaluate(self, context: FlagContext) -> bool:
        return context.environment in self.environments

    def to_dict(self) -> dict[str, Any]:
        return {"type": "environment", "environments": list(self.environments)}


class CompositeRule(TargetingRule):
    """Composite rule combining multiple rules."""

    def __init__(self, rules: list[TargetingRule], operator: str = "and"):
        self.rules = rules
        self.operator = operator  # "and", "or", "not"

    def evaluate(self, context: FlagContext) -> bool:
        if not self.rules:
            return True

        if self.operator == "and":
            return all(r.evaluate(context) for r in self.rules)
        elif self.operator == "or":
            return any(r.evaluate(context) for r in self.rules)
        elif self.operator == "not":
            return not self.rules[0].evaluate(context)
        else:
            return False

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "composite",
            "operator": self.operator,
            "rules": [r.to_dict() for r in self.rules],
        }


# =============================================================================
# Feature Flag
# =============================================================================


@dataclass
class FeatureFlag:
    """A feature flag configuration."""

    key: str
    flag_type: FlagType = FlagType.BOOLEAN
    state: FlagState = FlagState.DISABLED
    default_value: Any = False
    variants: list[Variant] = field(default_factory=list)
    targeting_rules: list[tuple[TargetingRule, Any]] = field(default_factory=list)
    description: str = ""
    tags: set[str] = field(default_factory=set)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    owner: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def evaluate(self, context: FlagContext | None = None) -> Any:
        """Evaluate the flag and return the appropriate value."""
        ctx = context or FlagContext()

        # If disabled, always return default
        if self.state == FlagState.DISABLED:
            return self.default_value

        # If enabled with no conditions, return enabled value
        if self.state == FlagState.ENABLED and not self.targeting_rules:
            # Variants take priority if defined
            if self.variants:
                return self._select_variant(ctx)
            if self.flag_type == FlagType.BOOLEAN:
                return True
            return self.default_value

        # Evaluate targeting rules
        for rule, value in self.targeting_rules:
            if rule.evaluate(ctx):
                if value is None and self.variants:
                    return self._select_variant(ctx)
                return value

        # No rules matched, return default
        return self.default_value

    def _select_variant(self, context: FlagContext) -> Any:
        """Select a variant based on context."""
        if not self.variants:
            return self.default_value

        # Weighted random selection based on context hash
        total_weight = sum(v.weight for v in self.variants)
        hash_key = context.hash_key(self.key)
        bucket = int(hash_key[:8], 16) % total_weight

        cumulative = 0
        for variant in self.variants:
            cumulative += variant.weight
            if bucket < cumulative:
                return variant.value

        return self.variants[-1].value

    def is_enabled(self, context: FlagContext | None = None) -> bool:
        """Check if the flag is enabled (for boolean flags)."""
        value = self.evaluate(context)
        return bool(value)

    def add_rule(self, rule: TargetingRule, value: Any = None) -> "FeatureFlag":
        """Add a targeting rule with its value."""
        self.targeting_rules.append((rule, value))
        self.state = FlagState.CONDITIONAL
        self.updated_at = datetime.now()
        return self

    def add_variant(self, name: str, value: Any, weight: int = 1) -> "FeatureFlag":
        """Add a variant."""
        self.variants.append(Variant(name=name, value=value, weight=weight))
        self.updated_at = datetime.now()
        return self

    def enable(self) -> "FeatureFlag":
        """Enable the flag."""
        self.state = FlagState.ENABLED
        self.updated_at = datetime.now()
        return self

    def disable(self) -> "FeatureFlag":
        """Disable the flag."""
        self.state = FlagState.DISABLED
        self.updated_at = datetime.now()
        return self

    def to_dict(self) -> dict[str, Any]:
        """Serialize the flag to a dictionary."""
        return {
            "key": self.key,
            "flag_type": self.flag_type.value,
            "state": self.state.value,
            "default_value": self.default_value,
            "variants": [
                {"name": v.name, "value": v.value, "weight": v.weight}
                for v in self.variants
            ],
            "targeting_rules": [
                {"rule": r.to_dict(), "value": v} for r, v in self.targeting_rules
            ],
            "description": self.description,
            "tags": list(self.tags),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "owner": self.owner,
            "metadata": self.metadata,
        }


# =============================================================================
# Flag Storage
# =============================================================================


class FlagStorage(ABC):
    """Abstract base for flag storage backends."""

    @abstractmethod
    def get(self, key: str) -> FeatureFlag | None:
        """Get a flag by key."""
        pass

    @abstractmethod
    def set(self, flag: FeatureFlag) -> None:
        """Store a flag."""
        pass

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete a flag."""
        pass

    @abstractmethod
    def list_all(self) -> list[FeatureFlag]:
        """List all flags."""
        pass


class MemoryFlagStorage(FlagStorage):
    """In-memory flag storage."""

    def __init__(self):
        self._flags: dict[str, FeatureFlag] = {}
        self._lock = threading.RLock()

    def get(self, key: str) -> FeatureFlag | None:
        with self._lock:
            return self._flags.get(key)

    def set(self, flag: FeatureFlag) -> None:
        with self._lock:
            self._flags[flag.key] = flag

    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._flags:
                del self._flags[key]
                return True
            return False

    def list_all(self) -> list[FeatureFlag]:
        with self._lock:
            return list(self._flags.values())


class FileFlagStorage(FlagStorage):
    """File-based flag storage (JSON)."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self._lock = threading.RLock()
        self._cache: dict[str, FeatureFlag] = {}
        self._load()

    def _load(self) -> None:
        """Load flags from file."""
        try:
            with open(self.file_path, "r") as f:
                data = json.load(f)
                for key, flag_data in data.items():
                    self._cache[key] = self._deserialize_flag(flag_data)
        except (FileNotFoundError, json.JSONDecodeError):
            self._cache = {}

    def _save(self) -> None:
        """Save flags to file."""
        data = {key: flag.to_dict() for key, flag in self._cache.items()}
        with open(self.file_path, "w") as f:
            json.dump(data, f, indent=2)

    def _deserialize_flag(self, data: dict[str, Any]) -> FeatureFlag:
        """Deserialize a flag from dictionary."""
        return FeatureFlag(
            key=data["key"],
            flag_type=FlagType(data.get("flag_type", "boolean")),
            state=FlagState(data.get("state", "disabled")),
            default_value=data.get("default_value", False),
            description=data.get("description", ""),
            tags=set(data.get("tags", [])),
            owner=data.get("owner", ""),
            metadata=data.get("metadata", {}),
        )

    def get(self, key: str) -> FeatureFlag | None:
        with self._lock:
            return self._cache.get(key)

    def set(self, flag: FeatureFlag) -> None:
        with self._lock:
            self._cache[flag.key] = flag
            self._save()

    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                self._save()
                return True
            return False

    def list_all(self) -> list[FeatureFlag]:
        with self._lock:
            return list(self._cache.values())


# =============================================================================
# Feature Flag Manager
# =============================================================================


@dataclass
class EvaluationResult:
    """Result of a flag evaluation."""

    flag_key: str
    value: Any
    variant: str | None = None
    reason: str = ""
    context_hash: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


class FeatureFlagManager:
    """Central manager for feature flags."""

    def __init__(
        self,
        storage: FlagStorage | None = None,
        default_context: FlagContext | None = None,
    ):
        self._storage = storage or MemoryFlagStorage()
        self._default_context = default_context or FlagContext()
        self._listeners: list[Callable[[str, Any, FlagContext], None]] = []
        self._overrides: dict[str, Any] = {}
        self._lock = threading.RLock()
        self._evaluation_history: list[EvaluationResult] = []
        self._max_history = 1000

    def create_flag(
        self,
        key: str,
        flag_type: FlagType = FlagType.BOOLEAN,
        default_value: Any = False,
        **kwargs,
    ) -> FeatureFlag:
        """Create a new feature flag."""
        flag = FeatureFlag(
            key=key, flag_type=flag_type, default_value=default_value, **kwargs
        )
        self._storage.set(flag)
        return flag

    def get_flag(self, key: str) -> FeatureFlag | None:
        """Get a flag by key."""
        return self._storage.get(key)

    def update_flag(self, flag: FeatureFlag) -> None:
        """Update an existing flag."""
        flag.updated_at = datetime.now()
        self._storage.set(flag)

    def delete_flag(self, key: str) -> bool:
        """Delete a flag."""
        return self._storage.delete(key)

    def list_flags(self, tags: set[str] | None = None) -> list[FeatureFlag]:
        """List all flags, optionally filtered by tags."""
        flags = self._storage.list_all()
        if tags:
            flags = [f for f in flags if f.tags & tags]
        return flags

    def evaluate(
        self, key: str, context: FlagContext | None = None, default: Any = None
    ) -> Any:
        """Evaluate a flag and return its value."""
        ctx = context or self._default_context

        # Check for override
        with self._lock:
            if key in self._overrides:
                return self._overrides[key]

        flag = self._storage.get(key)
        if not flag:
            if default is not None:
                return default
            raise FlagNotFoundError(f"Flag not found: {key}")

        value = flag.evaluate(ctx)

        # Record evaluation
        result = EvaluationResult(
            flag_key=key,
            value=value,
            reason=f"state={flag.state.value}",
            context_hash=ctx.hash_key(),
        )
        self._record_evaluation(result)

        # Notify listeners
        for listener in self._listeners:
            try:
                listener(key, value, ctx)
            except Exception:
                pass  # Don't let listener errors affect evaluation

        return value

    def is_enabled(
        self, key: str, context: FlagContext | None = None, default: bool = False
    ) -> bool:
        """Check if a boolean flag is enabled."""
        try:
            return bool(self.evaluate(key, context))
        except FlagNotFoundError:
            return default

    def get_variant(
        self, key: str, context: FlagContext | None = None, default: Any = None
    ) -> Any:
        """Get the variant value for a flag."""
        return self.evaluate(key, context, default)

    def set_override(self, key: str, value: Any) -> None:
        """Set a local override for testing."""
        with self._lock:
            self._overrides[key] = value

    def clear_override(self, key: str) -> None:
        """Clear a local override."""
        with self._lock:
            self._overrides.pop(key, None)

    def clear_all_overrides(self) -> None:
        """Clear all local overrides."""
        with self._lock:
            self._overrides.clear()

    def add_listener(self, listener: Callable[[str, Any, FlagContext], None]) -> None:
        """Add an evaluation listener."""
        self._listeners.append(listener)

    def remove_listener(
        self, listener: Callable[[str, Any, FlagContext], None]
    ) -> None:
        """Remove an evaluation listener."""
        if listener in self._listeners:
            self._listeners.remove(listener)

    def _record_evaluation(self, result: EvaluationResult) -> None:
        """Record an evaluation result."""
        with self._lock:
            self._evaluation_history.append(result)
            if len(self._evaluation_history) > self._max_history:
                self._evaluation_history = self._evaluation_history[
                    -self._max_history :
                ]

    def get_evaluation_history(self, limit: int = 100) -> list[EvaluationResult]:
        """Get recent evaluation history."""
        with self._lock:
            return self._evaluation_history[-limit:]

    def get_flag_stats(self, key: str) -> dict[str, Any]:
        """Get statistics for a flag."""
        with self._lock:
            evaluations = [e for e in self._evaluation_history if e.flag_key == key]

        if not evaluations:
            return {"total": 0}

        values = [e.value for e in evaluations]
        value_counts: dict[Any, int] = {}
        for v in values:
            v_str = str(v)
            value_counts[v_str] = value_counts.get(v_str, 0) + 1

        return {
            "total": len(evaluations),
            "value_distribution": value_counts,
            "unique_contexts": len(set(e.context_hash for e in evaluations)),
        }


# =============================================================================
# A/B Testing
# =============================================================================


@dataclass
class Experiment:
    """An A/B test experiment."""

    name: str
    description: str = ""
    variants: list[Variant] = field(default_factory=list)
    targeting: TargetingRule | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    traffic_percentage: float = 100.0
    is_active: bool = False
    created_at: datetime = field(default_factory=datetime.now)
    metrics: list[str] = field(default_factory=list)

    def is_running(self) -> bool:
        """Check if the experiment is currently running."""
        if not self.is_active:
            return False
        now = datetime.now()
        if self.start_time and now < self.start_time:
            return False
        if self.end_time and now > self.end_time:
            return False
        return True

    def get_variant(self, context: FlagContext) -> Variant | None:
        """Get the variant for a context."""
        if not self.is_running():
            return None

        # Check targeting
        if self.targeting and not self.targeting.evaluate(context):
            return None

        # Check traffic percentage
        traffic_rule = PercentageRule(self.traffic_percentage, self.name)
        if not traffic_rule.evaluate(context):
            return None

        # Select variant
        if not self.variants:
            return None

        total_weight = sum(v.weight for v in self.variants)
        hash_key = context.hash_key(self.name)
        bucket = int(hash_key[:8], 16) % total_weight

        cumulative = 0
        for variant in self.variants:
            cumulative += variant.weight
            if bucket < cumulative:
                return variant

        return self.variants[-1]


class ExperimentManager:
    """Manager for A/B test experiments."""

    def __init__(self):
        self._experiments: dict[str, Experiment] = {}
        self._assignments: dict[
            str, dict[str, str]
        ] = {}  # experiment -> user_id -> variant
        self._lock = threading.RLock()

    def create_experiment(
        self, name: str, variants: list[Variant], **kwargs
    ) -> Experiment:
        """Create a new experiment."""
        exp = Experiment(name=name, variants=variants, **kwargs)
        with self._lock:
            self._experiments[name] = exp
            self._assignments[name] = {}
        return exp

    def get_experiment(self, name: str) -> Experiment | None:
        """Get an experiment by name."""
        return self._experiments.get(name)

    def start_experiment(self, name: str) -> bool:
        """Start an experiment."""
        exp = self._experiments.get(name)
        if exp:
            exp.is_active = True
            return True
        return False

    def stop_experiment(self, name: str) -> bool:
        """Stop an experiment."""
        exp = self._experiments.get(name)
        if exp:
            exp.is_active = False
            return True
        return False

    def get_variant(self, experiment_name: str, context: FlagContext) -> Variant | None:
        """Get the variant for a user in an experiment."""
        exp = self._experiments.get(experiment_name)
        if not exp:
            return None

        # Check for existing assignment
        with self._lock:
            if context.user_id and context.user_id in self._assignments.get(
                experiment_name, {}
            ):
                variant_name = self._assignments[experiment_name][context.user_id]
                for v in exp.variants:
                    if v.name == variant_name:
                        return v

        # Get new assignment
        variant = exp.get_variant(context)

        # Store assignment
        if variant and context.user_id:
            with self._lock:
                if experiment_name not in self._assignments:
                    self._assignments[experiment_name] = {}
                self._assignments[experiment_name][context.user_id] = variant.name

        return variant

    def list_experiments(self, active_only: bool = False) -> list[Experiment]:
        """List all experiments."""
        exps = list(self._experiments.values())
        if active_only:
            exps = [e for e in exps if e.is_running()]
        return exps


# =============================================================================
# Gradual Rollout
# =============================================================================


@dataclass
class RolloutStage:
    """A stage in a gradual rollout."""

    percentage: float
    name: str = ""
    started_at: datetime | None = None
    completed_at: datetime | None = None


class GradualRollout:
    """Manages gradual feature rollouts."""

    def __init__(self, flag_key: str, manager: FeatureFlagManager):
        self.flag_key = flag_key
        self.manager = manager
        self.stages: list[RolloutStage] = []
        self.current_stage: int = -1
        self._salt = f"rollout_{flag_key}_{time.time()}"

    def add_stage(self, percentage: float, name: str = "") -> "GradualRollout":
        """Add a rollout stage."""
        if percentage < 0 or percentage > 100:
            raise FlagConfigurationError("Percentage must be between 0 and 100")
        if self.stages and percentage <= self.stages[-1].percentage:
            raise FlagConfigurationError("Stages must have increasing percentages")
        self.stages.append(RolloutStage(percentage=percentage, name=name))
        return self

    def advance(self) -> bool:
        """Advance to the next stage."""
        if self.current_stage >= len(self.stages) - 1:
            return False

        self.current_stage += 1
        stage = self.stages[self.current_stage]
        stage.started_at = datetime.now()

        # Update the flag with new percentage rule
        flag = self.manager.get_flag(self.flag_key)
        if flag:
            flag.targeting_rules = [
                (PercentageRule(stage.percentage, self._salt), True)
            ]
            flag.state = FlagState.CONDITIONAL
            self.manager.update_flag(flag)

        return True

    def rollback(self, stages: int = 1) -> bool:
        """Rollback to a previous stage."""
        new_stage = max(-1, self.current_stage - stages)
        if new_stage == self.current_stage:
            return False

        self.current_stage = new_stage

        flag = self.manager.get_flag(self.flag_key)
        if flag:
            if new_stage < 0:
                flag.targeting_rules = []
                flag.state = FlagState.DISABLED
            else:
                stage = self.stages[new_stage]
                flag.targeting_rules = [
                    (PercentageRule(stage.percentage, self._salt), True)
                ]
            self.manager.update_flag(flag)

        return True

    def complete(self) -> None:
        """Complete the rollout (enable for 100%)."""
        flag = self.manager.get_flag(self.flag_key)
        if flag:
            flag.targeting_rules = []
            flag.state = FlagState.ENABLED
            self.manager.update_flag(flag)

        if self.current_stage >= 0 and self.current_stage < len(self.stages):
            self.stages[self.current_stage].completed_at = datetime.now()

    def get_current_percentage(self) -> float:
        """Get the current rollout percentage."""
        if self.current_stage < 0:
            return 0.0
        if self.current_stage >= len(self.stages):
            return 100.0
        return self.stages[self.current_stage].percentage

    def get_status(self) -> dict[str, Any]:
        """Get the current rollout status."""
        return {
            "flag_key": self.flag_key,
            "current_stage": self.current_stage,
            "current_percentage": self.get_current_percentage(),
            "total_stages": len(self.stages),
            "stages": [
                {
                    "name": s.name,
                    "percentage": s.percentage,
                    "started_at": s.started_at.isoformat() if s.started_at else None,
                    "completed_at": s.completed_at.isoformat()
                    if s.completed_at
                    else None,
                }
                for s in self.stages
            ],
        }


# =============================================================================
# Convenience Functions
# =============================================================================

# Global default manager
_default_manager: FeatureFlagManager | None = None


def get_default_manager() -> FeatureFlagManager:
    """Get the default feature flag manager."""
    global _default_manager
    if _default_manager is None:
        _default_manager = FeatureFlagManager()
    return _default_manager


def set_default_manager(manager: FeatureFlagManager) -> None:
    """Set the default feature flag manager."""
    global _default_manager
    _default_manager = manager


def is_enabled(
    key: str, context: FlagContext | None = None, default: bool = False
) -> bool:
    """Check if a feature flag is enabled using the default manager."""
    return get_default_manager().is_enabled(key, context, default)


def get_variant(
    key: str, context: FlagContext | None = None, default: Any = None
) -> Any:
    """Get a feature flag variant using the default manager."""
    return get_default_manager().get_variant(key, context, default)


def feature_flag(key: str, default: bool = False):
    """Decorator to conditionally execute a function based on a feature flag."""

    def decorator(func):
        def wrapper(*args, **kwargs):
            if is_enabled(key, default=default):
                return func(*args, **kwargs)
            return None

        return wrapper

    return decorator
