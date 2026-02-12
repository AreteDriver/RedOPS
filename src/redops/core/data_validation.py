"""Data validation module for RedOPS.

Provides schema validation, data contracts, type coercion, and validation rules.
"""

import re
import json
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, date
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Type
from uuid import UUID
import ipaddress


class ValidationError(Exception):
    """Raised when validation fails."""

    def __init__(
        self,
        message: str,
        path: str | None = None,
        value: Any = None,
        errors: list["ValidationError"] | None = None,
    ):
        self.message = message
        self.path = path
        self.value = value
        self.errors = errors or []
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        if self.path:
            msg = f"{self.path}: {self.message}"
        else:
            msg = self.message
        if self.errors:
            nested = "; ".join(str(e) for e in self.errors)
            msg = f"{msg} [{nested}]"
        return msg


class CoercionError(Exception):
    """Raised when type coercion fails."""

    def __init__(self, value: Any, target_type: str, reason: str = ""):
        self.value = value
        self.target_type = target_type
        self.reason = reason
        super().__init__(
            f"Cannot coerce {type(value).__name__} to {target_type}: {reason}"
        )


# =============================================================================
# Validation Rules
# =============================================================================


class ValidationRule(ABC):
    """Base class for validation rules."""

    @abstractmethod
    def validate(self, value: Any, path: str = "") -> None:
        """Validate a value. Raise ValidationError if invalid."""
        pass

    @abstractmethod
    def describe(self) -> str:
        """Return human-readable description of the rule."""
        pass


class Required(ValidationRule):
    """Validates that a value is not None or empty."""

    def __init__(self, allow_empty: bool = False):
        self.allow_empty = allow_empty

    def validate(self, value: Any, path: str = "") -> None:
        if value is None:
            raise ValidationError("Value is required", path, value)
        if not self.allow_empty:
            if isinstance(value, str) and not value.strip():
                raise ValidationError("Value cannot be empty string", path, value)
            if isinstance(value, (list, dict, set)) and len(value) == 0:
                raise ValidationError("Value cannot be empty collection", path, value)

    def describe(self) -> str:
        return "required" if not self.allow_empty else "required (empty allowed)"


class TypeOf(ValidationRule):
    """Validates that a value is of a specific type."""

    def __init__(self, *types: Type):
        self.types = types

    def validate(self, value: Any, path: str = "") -> None:
        if value is not None and not isinstance(value, self.types):
            type_names = ", ".join(t.__name__ for t in self.types)
            raise ValidationError(
                f"Expected type {type_names}, got {type(value).__name__}", path, value
            )

    def describe(self) -> str:
        return f"type: {', '.join(t.__name__ for t in self.types)}"


class Range(ValidationRule):
    """Validates that a numeric value is within a range."""

    def __init__(
        self,
        min_val: float | None = None,
        max_val: float | None = None,
        exclusive_min: bool = False,
        exclusive_max: bool = False,
    ):
        self.min_val = min_val
        self.max_val = max_val
        self.exclusive_min = exclusive_min
        self.exclusive_max = exclusive_max

    def validate(self, value: Any, path: str = "") -> None:
        if value is None:
            return

        try:
            num = float(value)
        except (TypeError, ValueError):
            raise ValidationError("Value must be numeric for range check", path, value)

        if self.min_val is not None:
            if self.exclusive_min:
                if num <= self.min_val:
                    raise ValidationError(
                        f"Value must be > {self.min_val}", path, value
                    )
            else:
                if num < self.min_val:
                    raise ValidationError(
                        f"Value must be >= {self.min_val}", path, value
                    )

        if self.max_val is not None:
            if self.exclusive_max:
                if num >= self.max_val:
                    raise ValidationError(
                        f"Value must be < {self.max_val}", path, value
                    )
            else:
                if num > self.max_val:
                    raise ValidationError(
                        f"Value must be <= {self.max_val}", path, value
                    )

    def describe(self) -> str:
        parts = []
        if self.min_val is not None:
            op = ">" if self.exclusive_min else ">="
            parts.append(f"{op} {self.min_val}")
        if self.max_val is not None:
            op = "<" if self.exclusive_max else "<="
            parts.append(f"{op} {self.max_val}")
        return f"range: {' and '.join(parts)}" if parts else "any range"


class Length(ValidationRule):
    """Validates the length of a string, list, or other sequence."""

    def __init__(
        self,
        min_len: int | None = None,
        max_len: int | None = None,
        exact: int | None = None,
    ):
        self.min_len = min_len
        self.max_len = max_len
        self.exact = exact

    def validate(self, value: Any, path: str = "") -> None:
        if value is None:
            return

        try:
            length = len(value)
        except TypeError:
            raise ValidationError("Value must have a length", path, value)

        if self.exact is not None:
            if length != self.exact:
                raise ValidationError(
                    f"Length must be exactly {self.exact}, got {length}", path, value
                )
            return

        if self.min_len is not None and length < self.min_len:
            raise ValidationError(
                f"Length must be >= {self.min_len}, got {length}", path, value
            )

        if self.max_len is not None and length > self.max_len:
            raise ValidationError(
                f"Length must be <= {self.max_len}, got {length}", path, value
            )

    def describe(self) -> str:
        if self.exact is not None:
            return f"length: exactly {self.exact}"
        parts = []
        if self.min_len is not None:
            parts.append(f">= {self.min_len}")
        if self.max_len is not None:
            parts.append(f"<= {self.max_len}")
        return f"length: {' and '.join(parts)}" if parts else "any length"


class Pattern(ValidationRule):
    """Validates that a string matches a regex pattern."""

    def __init__(self, pattern: str | re.Pattern, description: str = ""):
        if isinstance(pattern, str):
            self.pattern = re.compile(pattern)
        else:
            self.pattern = pattern
        self.description_text = description

    def validate(self, value: Any, path: str = "") -> None:
        if value is None:
            return

        if not isinstance(value, str):
            raise ValidationError(
                "Value must be a string for pattern matching", path, value
            )

        if not self.pattern.match(value):
            desc = self.description_text or self.pattern.pattern
            raise ValidationError(f"Value does not match pattern: {desc}", path, value)

    def describe(self) -> str:
        return self.description_text or f"pattern: {self.pattern.pattern}"


class OneOf(ValidationRule):
    """Validates that a value is one of the allowed values."""

    def __init__(self, *allowed: Any, case_sensitive: bool = True):
        self.allowed = set(allowed)
        self.case_sensitive = case_sensitive
        if not case_sensitive:
            self._lower_allowed = {
                v.lower() if isinstance(v, str) else v for v in allowed
            }

    def validate(self, value: Any, path: str = "") -> None:
        if value is None:
            return

        check_value = value
        check_set = self.allowed

        if not self.case_sensitive and isinstance(value, str):
            check_value = value.lower()
            check_set = self._lower_allowed

        if check_value not in check_set:
            raise ValidationError(
                f"Value must be one of: {sorted(str(v) for v in self.allowed)}",
                path,
                value,
            )

    def describe(self) -> str:
        return f"one of: {sorted(str(v) for v in self.allowed)}"


class NoneOf(ValidationRule):
    """Validates that a value is not one of the forbidden values."""

    def __init__(self, *forbidden: Any):
        self.forbidden = set(forbidden)

    def validate(self, value: Any, path: str = "") -> None:
        if value is None:
            return

        if value in self.forbidden:
            raise ValidationError(
                f"Value must not be one of: {sorted(str(v) for v in self.forbidden)}",
                path,
                value,
            )

    def describe(self) -> str:
        return f"none of: {sorted(str(v) for v in self.forbidden)}"


class Email(ValidationRule):
    """Validates email format."""

    _EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

    def validate(self, value: Any, path: str = "") -> None:
        if value is None:
            return

        if not isinstance(value, str):
            raise ValidationError("Email must be a string", path, value)

        if not self._EMAIL_PATTERN.match(value):
            raise ValidationError("Invalid email format", path, value)

    def describe(self) -> str:
        return "valid email"


class URL(ValidationRule):
    """Validates URL format."""

    _URL_PATTERN = re.compile(
        r"^https?://[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)*"
        r"(:\d+)?(/[-a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=%]*)?$"
    )

    def __init__(self, schemes: list[str] | None = None):
        self.schemes = schemes or ["http", "https"]

    def validate(self, value: Any, path: str = "") -> None:
        if value is None:
            return

        if not isinstance(value, str):
            raise ValidationError("URL must be a string", path, value)

        if not self._URL_PATTERN.match(value):
            raise ValidationError("Invalid URL format", path, value)

        scheme = value.split("://")[0].lower()
        if scheme not in self.schemes:
            raise ValidationError(
                f"URL scheme must be one of: {self.schemes}", path, value
            )

    def describe(self) -> str:
        return f"valid URL ({', '.join(self.schemes)})"


class IPAddress(ValidationRule):
    """Validates IP address format."""

    def __init__(self, version: int | None = None):
        self.version = version  # 4, 6, or None for any

    def validate(self, value: Any, path: str = "") -> None:
        if value is None:
            return

        if not isinstance(value, str):
            raise ValidationError("IP address must be a string", path, value)

        try:
            addr = ipaddress.ip_address(value)
            if self.version == 4 and not isinstance(addr, ipaddress.IPv4Address):
                raise ValidationError("Expected IPv4 address", path, value)
            if self.version == 6 and not isinstance(addr, ipaddress.IPv6Address):
                raise ValidationError("Expected IPv6 address", path, value)
        except ValueError:
            raise ValidationError("Invalid IP address format", path, value)

    def describe(self) -> str:
        if self.version:
            return f"valid IPv{self.version} address"
        return "valid IP address"


class UUID4(ValidationRule):
    """Validates UUID format."""

    def validate(self, value: Any, path: str = "") -> None:
        if value is None:
            return

        if isinstance(value, UUID):
            return

        if not isinstance(value, str):
            raise ValidationError("UUID must be a string", path, value)

        try:
            UUID(value)
        except ValueError:
            raise ValidationError("Invalid UUID format", path, value)

    def describe(self) -> str:
        return "valid UUID"


class DateFormat(ValidationRule):
    """Validates date/datetime string format."""

    def __init__(self, fmt: str = "%Y-%m-%d"):
        self.fmt = fmt

    def validate(self, value: Any, path: str = "") -> None:
        if value is None:
            return

        if isinstance(value, (datetime, date)):
            return

        if not isinstance(value, str):
            raise ValidationError("Date must be a string", path, value)

        try:
            datetime.strptime(value, self.fmt)
        except ValueError:
            raise ValidationError(
                f"Invalid date format, expected {self.fmt}", path, value
            )

    def describe(self) -> str:
        return f"date format: {self.fmt}"


class Custom(ValidationRule):
    """Custom validation using a callable."""

    def __init__(
        self,
        validator: Callable[[Any], bool],
        message: str,
        description: str = "custom rule",
    ):
        self.validator = validator
        self.message = message
        self.description_text = description

    def validate(self, value: Any, path: str = "") -> None:
        if value is None:
            return

        try:
            if not self.validator(value):
                raise ValidationError(self.message, path, value)
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"{self.message}: {e}", path, value)

    def describe(self) -> str:
        return self.description_text


class All(ValidationRule):
    """All rules must pass."""

    def __init__(self, *rules: ValidationRule):
        self.rules = rules

    def validate(self, value: Any, path: str = "") -> None:
        for rule in self.rules:
            rule.validate(value, path)

    def describe(self) -> str:
        return " AND ".join(r.describe() for r in self.rules)


class Any_(ValidationRule):
    """At least one rule must pass."""

    def __init__(self, *rules: ValidationRule):
        self.rules = rules

    def validate(self, value: Any, path: str = "") -> None:
        if not self.rules:
            return

        errors = []
        for rule in self.rules:
            try:
                rule.validate(value, path)
                return  # Success
            except ValidationError as e:
                errors.append(e)

        raise ValidationError("None of the rules passed", path, value, errors)

    def describe(self) -> str:
        return " OR ".join(r.describe() for r in self.rules)


# =============================================================================
# Type Coercion
# =============================================================================


class TypeCoercer:
    """Handles type coercion with configurable strictness."""

    def __init__(self, strict: bool = False):
        self.strict = strict
        self._coercers: dict[type, Callable[[Any], Any]] = {
            str: self._to_str,
            int: self._to_int,
            float: self._to_float,
            bool: self._to_bool,
            Decimal: self._to_decimal,
            datetime: self._to_datetime,
            date: self._to_date,
            list: self._to_list,
            dict: self._to_dict,
            UUID: self._to_uuid,
        }

    def coerce(self, value: Any, target_type: Type) -> Any:
        """Coerce a value to the target type."""
        if value is None:
            return None

        if isinstance(value, target_type):
            return value

        if self.strict:
            raise CoercionError(value, target_type.__name__, "strict mode enabled")

        coercer = self._coercers.get(target_type)
        if coercer:
            return coercer(value)

        # Try direct conversion
        try:
            return target_type(value)
        except Exception as e:
            raise CoercionError(value, target_type.__name__, str(e))

    def _to_str(self, value: Any) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8")
        return str(value)

    def _to_int(self, value: Any) -> int:
        if isinstance(value, bool):
            return 1 if value else 0
        if isinstance(value, str):
            # Handle float strings
            if "." in value:
                return int(float(value))
            return int(value)
        return int(value)

    def _to_float(self, value: Any) -> float:
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        return float(value)

    def _to_bool(self, value: Any) -> bool:
        if isinstance(value, str):
            lower = value.lower().strip()
            if lower in ("true", "1", "yes", "on", "y"):
                return True
            if lower in ("false", "0", "no", "off", "n", ""):
                return False
            raise CoercionError(value, "bool", f"unknown boolean string: {value}")
        return bool(value)

    def _to_decimal(self, value: Any) -> Decimal:
        try:
            return Decimal(str(value))
        except InvalidOperation:
            raise CoercionError(value, "Decimal", "invalid decimal format")

    def _to_datetime(self, value: Any) -> datetime:
        if isinstance(value, datetime):
            return value
        if isinstance(value, date):
            return datetime.combine(value, datetime.min.time())
        if isinstance(value, str):
            # Try common formats
            formats = [
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d",
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue
            raise CoercionError(value, "datetime", "unrecognized format")
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value)
        raise CoercionError(value, "datetime", f"cannot convert {type(value).__name__}")

    def _to_date(self, value: Any) -> date:
        if isinstance(value, datetime):
            return value.date()
        if isinstance(value, date):
            return value
        if isinstance(value, str):
            try:
                return datetime.strptime(value, "%Y-%m-%d").date()
            except ValueError:
                raise CoercionError(value, "date", "expected YYYY-MM-DD format")
        raise CoercionError(value, "date", f"cannot convert {type(value).__name__}")

    def _to_list(self, value: Any) -> list:
        if isinstance(value, str):
            # Try JSON
            try:
                result = json.loads(value)
                if isinstance(result, list):
                    return result
            except json.JSONDecodeError:
                pass  # Not JSON - fall through to comma-split
            # Split by comma
            return [v.strip() for v in value.split(",") if v.strip()]
        if isinstance(value, (tuple, set, frozenset)):
            return list(value)
        raise CoercionError(value, "list", f"cannot convert {type(value).__name__}")

    def _to_dict(self, value: Any) -> dict:
        if isinstance(value, str):
            try:
                result = json.loads(value)
                if isinstance(result, dict):
                    return result
            except json.JSONDecodeError:
                raise CoercionError(value, "dict", "invalid JSON")
        raise CoercionError(value, "dict", f"cannot convert {type(value).__name__}")

    def _to_uuid(self, value: Any) -> UUID:
        if isinstance(value, UUID):
            return value
        if isinstance(value, str):
            try:
                return UUID(value)
            except ValueError:
                raise CoercionError(value, "UUID", "invalid UUID format")
        raise CoercionError(value, "UUID", f"cannot convert {type(value).__name__}")


# =============================================================================
# Schema Definition
# =============================================================================


@dataclass
class FieldSpec:
    """Specification for a single field in a schema."""

    name: str
    type: Type | None = None
    rules: list[ValidationRule] = field(default_factory=list)
    default: Any = None
    nullable: bool = True
    coerce: bool = False
    alias: str | None = None
    description: str = ""

    def validate(
        self, value: Any, coercer: TypeCoercer | None = None
    ) -> tuple[Any, list[ValidationError]]:
        """Validate and optionally coerce a value. Returns (value, errors)."""
        errors = []

        # Handle None
        if value is None:
            if not self.nullable:
                errors.append(ValidationError("Value cannot be null", self.name))
            elif self.default is not None:
                return self.default, []
            return None, errors

        # Type coercion (if coercer provided, either from schema or field level)
        if self.type and coercer:
            try:
                value = coercer.coerce(value, self.type)
            except CoercionError as e:
                errors.append(ValidationError(str(e), self.name, value))
                return value, errors

        # Type check
        if self.type and not isinstance(value, self.type):
            errors.append(
                ValidationError(
                    f"Expected {self.type.__name__}, got {type(value).__name__}",
                    self.name,
                    value,
                )
            )

        # Rule validation
        for rule in self.rules:
            try:
                rule.validate(value, self.name)
            except ValidationError as e:
                errors.append(e)

        return value, errors


class Schema:
    """Schema for validating dictionaries/objects."""

    def __init__(
        self,
        fields: list[FieldSpec] | None = None,
        strict: bool = False,
        coerce: bool = False,
    ):
        self.fields: dict[str, FieldSpec] = {}
        self.aliases: dict[str, str] = {}  # alias -> field name
        self.strict = strict
        self.coerce = coerce
        self.coercer = TypeCoercer(strict=False)

        if fields:
            for f in fields:
                self.add_field(f)

    def add_field(self, spec: FieldSpec) -> "Schema":
        """Add a field specification."""
        self.fields[spec.name] = spec
        if spec.alias:
            self.aliases[spec.alias] = spec.name
        return self

    def field(self, name: str, type: Type | None = None, **kwargs) -> "Schema":
        """Fluent API for adding fields."""
        rules = kwargs.pop("rules", [])
        spec = FieldSpec(name=name, type=type, rules=rules, **kwargs)
        return self.add_field(spec)

    def validate(
        self, data: dict[str, Any], raise_on_error: bool = True
    ) -> "ValidationResult":
        """Validate data against the schema."""
        result = ValidationResult()
        validated = {}

        if not isinstance(data, dict):
            result.add_error(ValidationError("Data must be a dictionary"))
            if raise_on_error:
                raise result.errors[0]
            return result

        # Resolve aliases
        resolved_data = {}
        for key, value in data.items():
            if key in self.aliases:
                resolved_data[self.aliases[key]] = value
            else:
                resolved_data[key] = value

        # Check for unknown fields in strict mode
        if self.strict:
            unknown = set(resolved_data.keys()) - set(self.fields.keys())
            for key in unknown:
                result.add_error(ValidationError(f"Unknown field: {key}"))

        # Validate each field
        for name, spec in self.fields.items():
            value = resolved_data.get(name, spec.default)

            # Use schema-level coerce setting if field doesn't override
            coercer = self.coercer if (spec.coerce or self.coerce) else None

            validated_value, errors = spec.validate(value, coercer)
            validated[name] = validated_value

            for error in errors:
                result.add_error(error)

        result.data = validated

        if raise_on_error and result.errors:
            raise ValidationError("Schema validation failed", errors=result.errors)

        return result

    def to_dict(self) -> dict[str, Any]:
        """Export schema as dictionary."""
        return {
            "strict": self.strict,
            "coerce": self.coerce,
            "fields": {
                name: {
                    "type": spec.type.__name__ if spec.type else None,
                    "nullable": spec.nullable,
                    "default": spec.default,
                    "coerce": spec.coerce,
                    "alias": spec.alias,
                    "description": spec.description,
                    "rules": [r.describe() for r in spec.rules],
                }
                for name, spec in self.fields.items()
            },
        }


@dataclass
class ValidationResult:
    """Result of a validation operation."""

    data: dict[str, Any] = field(default_factory=dict)
    errors: list[ValidationError] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def add_error(self, error: ValidationError) -> None:
        self.errors.append(error)

    def error_messages(self) -> list[str]:
        return [str(e) for e in self.errors]


# =============================================================================
# Data Contracts
# =============================================================================


class ContractViolation(Exception):
    """Raised when a data contract is violated."""

    pass


@dataclass
class DataContract:
    """Defines a contract between data producer and consumer."""

    name: str
    version: str
    schema: Schema
    producer: str = ""
    consumer: str = ""
    description: str = ""
    created_at: datetime = field(default_factory=datetime.now)

    def validate(self, data: dict[str, Any]) -> ValidationResult:
        """Validate data against contract schema."""
        return self.schema.validate(data, raise_on_error=False)

    def enforce(self, data: dict[str, Any]) -> dict[str, Any]:
        """Enforce contract, raising ContractViolation on failure."""
        result = self.validate(data)
        if not result.is_valid:
            raise ContractViolation(
                f"Contract '{self.name}' v{self.version} violated: "
                f"{'; '.join(result.error_messages())}"
            )
        return result.data

    def fingerprint(self) -> str:
        """Generate a fingerprint for this contract version."""
        schema_json = json.dumps(self.schema.to_dict(), sort_keys=True)
        content = f"{self.name}:{self.version}:{schema_json}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def is_compatible(self, other: "DataContract") -> bool:
        """Check if this contract is compatible with another (newer) version."""
        # Same fields with same or looser constraints = compatible
        for name, spec in self.schema.fields.items():
            if name not in other.schema.fields:
                return False  # Field removed
        return True


class ContractRegistry:
    """Registry for managing data contracts."""

    def __init__(self):
        self._contracts: dict[
            str, dict[str, DataContract]
        ] = {}  # name -> version -> contract

    def register(self, contract: DataContract) -> None:
        """Register a contract."""
        if contract.name not in self._contracts:
            self._contracts[contract.name] = {}
        self._contracts[contract.name][contract.version] = contract

    def get(self, name: str, version: str | None = None) -> DataContract | None:
        """Get a contract by name and optional version. Returns latest if no version."""
        if name not in self._contracts:
            return None

        versions = self._contracts[name]
        if version:
            return versions.get(version)

        # Return latest version
        if not versions:
            return None
        latest = sorted(versions.keys())[-1]
        return versions[latest]

    def list_contracts(self) -> list[tuple[str, str]]:
        """List all registered contracts as (name, version) tuples."""
        result = []
        for name, versions in self._contracts.items():
            for version in versions:
                result.append((name, version))
        return sorted(result)

    def validate(
        self, contract_name: str, data: dict[str, Any], version: str | None = None
    ) -> ValidationResult:
        """Validate data against a registered contract."""
        contract = self.get(contract_name, version)
        if not contract:
            result = ValidationResult()
            result.add_error(ValidationError(f"Contract not found: {contract_name}"))
            return result
        return contract.validate(data)


# =============================================================================
# Validators for common security data types
# =============================================================================


class SecurityValidators:
    """Pre-built validators for security-related data."""

    @staticmethod
    def ipv4() -> ValidationRule:
        return IPAddress(version=4)

    @staticmethod
    def ipv6() -> ValidationRule:
        return IPAddress(version=6)

    @staticmethod
    def mac_address() -> ValidationRule:
        return Pattern(
            r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$",
            "MAC address (XX:XX:XX:XX:XX:XX)",
        )

    @staticmethod
    def hostname() -> ValidationRule:
        return Pattern(
            r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
            r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$",
            "valid hostname",
        )

    @staticmethod
    def port() -> ValidationRule:
        return Range(min_val=1, max_val=65535)

    @staticmethod
    def md5_hash() -> ValidationRule:
        return Pattern(r"^[a-fA-F0-9]{32}$", "MD5 hash")

    @staticmethod
    def sha1_hash() -> ValidationRule:
        return Pattern(r"^[a-fA-F0-9]{40}$", "SHA1 hash")

    @staticmethod
    def sha256_hash() -> ValidationRule:
        return Pattern(r"^[a-fA-F0-9]{64}$", "SHA256 hash")

    @staticmethod
    def cve_id() -> ValidationRule:
        return Pattern(r"^CVE-\d{4}-\d{4,}$", "CVE ID (CVE-YYYY-NNNNN)")

    @staticmethod
    def severity() -> ValidationRule:
        return OneOf("critical", "high", "medium", "low", "info", case_sensitive=False)

    @staticmethod
    def cvss_score() -> ValidationRule:
        return Range(min_val=0.0, max_val=10.0)

    @staticmethod
    def mitre_technique() -> ValidationRule:
        return Pattern(r"^T\d{4}(\.\d{3})?$", "MITRE ATT&CK technique ID")

    @staticmethod
    def base64_data() -> ValidationRule:
        return Pattern(r"^[A-Za-z0-9+/]*={0,2}$", "Base64 encoded data")


# =============================================================================
# Convenience functions
# =============================================================================


def validate_dict(data: dict[str, Any], schema: Schema) -> ValidationResult:
    """Validate a dictionary against a schema."""
    return schema.validate(data, raise_on_error=False)


def validate_list(
    items: list[dict[str, Any]], schema: Schema
) -> list[ValidationResult]:
    """Validate a list of items against a schema."""
    return [schema.validate(item, raise_on_error=False) for item in items]


def create_schema(**field_specs) -> Schema:
    """Quick schema creation from field specifications.

    Example:
        schema = create_schema(
            name=(str, Required()),
            age=(int, Range(0, 150)),
            email=(str, Email())
        )
    """
    schema = Schema()
    for name, spec in field_specs.items():
        if isinstance(spec, tuple):
            field_type = spec[0] if len(spec) > 0 else None
            rules = list(spec[1:]) if len(spec) > 1 else []
            schema.field(name, type=field_type, rules=rules)
        else:
            schema.field(name, type=spec)
    return schema
