"""Tests for data validation module."""

import pytest
from datetime import datetime, date
from decimal import Decimal
from uuid import UUID, uuid4

from redops.core.data_validation import (
    # Exceptions
    ValidationError, CoercionError, ContractViolation,
    # Rules
    ValidationRule, Required, TypeOf, Range, Length, Pattern,
    OneOf, NoneOf, Email, URL, IPAddress, UUID4, DateFormat,
    Custom, All, Any_,
    # Coercion
    TypeCoercer,
    # Schema
    FieldSpec, Schema, ValidationResult,
    # Contracts
    DataContract, ContractRegistry,
    # Security validators
    SecurityValidators,
    # Utilities
    validate_dict, validate_list, create_schema,
)


# =============================================================================
# ValidationError Tests
# =============================================================================

class TestValidationError:
    """Tests for ValidationError."""

    def test_basic_error(self):
        """Test basic error creation."""
        err = ValidationError("test error")
        assert err.message == "test error"
        assert err.path is None
        assert err.value is None
        assert str(err) == "test error"

    def test_error_with_path(self):
        """Test error with path."""
        err = ValidationError("invalid", path="user.email")
        assert "user.email" in str(err)

    def test_error_with_nested(self):
        """Test error with nested errors."""
        nested = [
            ValidationError("error 1"),
            ValidationError("error 2"),
        ]
        err = ValidationError("multiple", errors=nested)
        assert "error 1" in str(err)
        assert "error 2" in str(err)


# =============================================================================
# Required Rule Tests
# =============================================================================

class TestRequiredRule:
    """Tests for Required validation rule."""

    def test_none_fails(self):
        """Test that None fails validation."""
        rule = Required()
        with pytest.raises(ValidationError):
            rule.validate(None)

    def test_empty_string_fails(self):
        """Test that empty string fails by default."""
        rule = Required()
        with pytest.raises(ValidationError):
            rule.validate("")

    def test_empty_string_allowed(self):
        """Test that empty string can be allowed."""
        rule = Required(allow_empty=True)
        rule.validate("")  # Should not raise

    def test_empty_list_fails(self):
        """Test that empty list fails."""
        rule = Required()
        with pytest.raises(ValidationError):
            rule.validate([])

    def test_valid_value_passes(self):
        """Test that valid values pass."""
        rule = Required()
        rule.validate("hello")
        rule.validate([1, 2, 3])
        rule.validate({"key": "value"})
        rule.validate(0)  # Zero is valid

    def test_describe(self):
        """Test rule description."""
        assert "required" in Required().describe()


# =============================================================================
# TypeOf Rule Tests
# =============================================================================

class TestTypeOfRule:
    """Tests for TypeOf validation rule."""

    def test_single_type(self):
        """Test single type validation."""
        rule = TypeOf(str)
        rule.validate("hello")
        with pytest.raises(ValidationError):
            rule.validate(123)

    def test_multiple_types(self):
        """Test multiple type validation."""
        rule = TypeOf(str, int)
        rule.validate("hello")
        rule.validate(123)
        with pytest.raises(ValidationError):
            rule.validate([1, 2])

    def test_none_passes(self):
        """Test that None passes type check."""
        rule = TypeOf(str)
        rule.validate(None)  # Should not raise


# =============================================================================
# Range Rule Tests
# =============================================================================

class TestRangeRule:
    """Tests for Range validation rule."""

    def test_min_only(self):
        """Test minimum bound only."""
        rule = Range(min_val=0)
        rule.validate(0)
        rule.validate(100)
        with pytest.raises(ValidationError):
            rule.validate(-1)

    def test_max_only(self):
        """Test maximum bound only."""
        rule = Range(max_val=100)
        rule.validate(100)
        rule.validate(-50)
        with pytest.raises(ValidationError):
            rule.validate(101)

    def test_both_bounds(self):
        """Test both bounds."""
        rule = Range(min_val=0, max_val=100)
        rule.validate(50)
        with pytest.raises(ValidationError):
            rule.validate(-1)
        with pytest.raises(ValidationError):
            rule.validate(101)

    def test_exclusive_bounds(self):
        """Test exclusive bounds."""
        rule = Range(min_val=0, max_val=100, exclusive_min=True, exclusive_max=True)
        rule.validate(50)
        with pytest.raises(ValidationError):
            rule.validate(0)  # Exclusive
        with pytest.raises(ValidationError):
            rule.validate(100)  # Exclusive

    def test_non_numeric_fails(self):
        """Test that non-numeric values fail."""
        rule = Range(min_val=0)
        with pytest.raises(ValidationError):
            rule.validate("not a number")


# =============================================================================
# Length Rule Tests
# =============================================================================

class TestLengthRule:
    """Tests for Length validation rule."""

    def test_min_length(self):
        """Test minimum length."""
        rule = Length(min_len=5)
        rule.validate("hello")
        with pytest.raises(ValidationError):
            rule.validate("hi")

    def test_max_length(self):
        """Test maximum length."""
        rule = Length(max_len=5)
        rule.validate("hello")
        with pytest.raises(ValidationError):
            rule.validate("hello world")

    def test_exact_length(self):
        """Test exact length."""
        rule = Length(exact=5)
        rule.validate("hello")
        with pytest.raises(ValidationError):
            rule.validate("hi")
        with pytest.raises(ValidationError):
            rule.validate("hello world")

    def test_list_length(self):
        """Test length validation on lists."""
        rule = Length(min_len=2, max_len=4)
        rule.validate([1, 2, 3])
        with pytest.raises(ValidationError):
            rule.validate([1])


# =============================================================================
# Pattern Rule Tests
# =============================================================================

class TestPatternRule:
    """Tests for Pattern validation rule."""

    def test_matches(self):
        """Test matching pattern."""
        rule = Pattern(r'^[A-Z]{3}-\d{4}$')
        rule.validate("ABC-1234")

    def test_no_match(self):
        """Test non-matching pattern."""
        rule = Pattern(r'^[A-Z]{3}-\d{4}$')
        with pytest.raises(ValidationError):
            rule.validate("invalid")

    def test_non_string_fails(self):
        """Test that non-strings fail."""
        rule = Pattern(r'.*')
        with pytest.raises(ValidationError):
            rule.validate(123)

    def test_compiled_pattern(self):
        """Test with pre-compiled pattern."""
        import re
        compiled = re.compile(r'^\d+$')
        rule = Pattern(compiled)
        rule.validate("123")


# =============================================================================
# OneOf Rule Tests
# =============================================================================

class TestOneOfRule:
    """Tests for OneOf validation rule."""

    def test_valid_choice(self):
        """Test valid choice."""
        rule = OneOf('red', 'green', 'blue')
        rule.validate('red')

    def test_invalid_choice(self):
        """Test invalid choice."""
        rule = OneOf('red', 'green', 'blue')
        with pytest.raises(ValidationError):
            rule.validate('yellow')

    def test_case_insensitive(self):
        """Test case insensitive matching."""
        rule = OneOf('red', 'green', 'blue', case_sensitive=False)
        rule.validate('RED')
        rule.validate('Green')


# =============================================================================
# NoneOf Rule Tests
# =============================================================================

class TestNoneOfRule:
    """Tests for NoneOf validation rule."""

    def test_valid_value(self):
        """Test value not in forbidden list."""
        rule = NoneOf('admin', 'root', 'system')
        rule.validate('user')

    def test_forbidden_value(self):
        """Test forbidden value."""
        rule = NoneOf('admin', 'root', 'system')
        with pytest.raises(ValidationError):
            rule.validate('admin')


# =============================================================================
# Email Rule Tests
# =============================================================================

class TestEmailRule:
    """Tests for Email validation rule."""

    def test_valid_emails(self):
        """Test valid email formats."""
        rule = Email()
        rule.validate("user@example.com")
        rule.validate("user.name@domain.org")
        rule.validate("user+tag@example.co.uk")

    def test_invalid_emails(self):
        """Test invalid email formats."""
        rule = Email()
        with pytest.raises(ValidationError):
            rule.validate("invalid")
        with pytest.raises(ValidationError):
            rule.validate("@missing.com")
        with pytest.raises(ValidationError):
            rule.validate("user@")


# =============================================================================
# URL Rule Tests
# =============================================================================

class TestURLRule:
    """Tests for URL validation rule."""

    def test_valid_urls(self):
        """Test valid URL formats."""
        rule = URL()
        rule.validate("https://example.com")
        rule.validate("http://example.com/path")
        rule.validate("https://sub.example.com:8080/path?query=1")

    def test_invalid_urls(self):
        """Test invalid URL formats."""
        rule = URL()
        with pytest.raises(ValidationError):
            rule.validate("not a url")
        with pytest.raises(ValidationError):
            rule.validate("ftp://example.com")  # Wrong scheme


# =============================================================================
# IPAddress Rule Tests
# =============================================================================

class TestIPAddressRule:
    """Tests for IPAddress validation rule."""

    def test_ipv4(self):
        """Test IPv4 validation."""
        rule = IPAddress(version=4)
        rule.validate("192.168.1.1")
        with pytest.raises(ValidationError):
            rule.validate("::1")  # IPv6

    def test_ipv6(self):
        """Test IPv6 validation."""
        rule = IPAddress(version=6)
        rule.validate("::1")
        rule.validate("2001:db8::1")
        with pytest.raises(ValidationError):
            rule.validate("192.168.1.1")  # IPv4

    def test_any_version(self):
        """Test any IP version."""
        rule = IPAddress()
        rule.validate("192.168.1.1")
        rule.validate("::1")

    def test_invalid_ip(self):
        """Test invalid IP address."""
        rule = IPAddress()
        with pytest.raises(ValidationError):
            rule.validate("999.999.999.999")


# =============================================================================
# UUID Rule Tests
# =============================================================================

class TestUUID4Rule:
    """Tests for UUID4 validation rule."""

    def test_valid_uuid_string(self):
        """Test valid UUID string."""
        rule = UUID4()
        rule.validate("550e8400-e29b-41d4-a716-446655440000")

    def test_valid_uuid_object(self):
        """Test valid UUID object."""
        rule = UUID4()
        rule.validate(uuid4())

    def test_invalid_uuid(self):
        """Test invalid UUID."""
        rule = UUID4()
        with pytest.raises(ValidationError):
            rule.validate("not-a-uuid")


# =============================================================================
# DateFormat Rule Tests
# =============================================================================

class TestDateFormatRule:
    """Tests for DateFormat validation rule."""

    def test_default_format(self):
        """Test default date format."""
        rule = DateFormat()
        rule.validate("2024-01-15")

    def test_custom_format(self):
        """Test custom date format."""
        rule = DateFormat("%d/%m/%Y")
        rule.validate("15/01/2024")

    def test_datetime_object(self):
        """Test datetime object passes."""
        rule = DateFormat()
        rule.validate(datetime.now())

    def test_invalid_format(self):
        """Test invalid date format."""
        rule = DateFormat()
        with pytest.raises(ValidationError):
            rule.validate("15-01-2024")


# =============================================================================
# Custom Rule Tests
# =============================================================================

class TestCustomRule:
    """Tests for Custom validation rule."""

    def test_passing_validator(self):
        """Test passing custom validator."""
        rule = Custom(lambda x: x > 0, "must be positive")
        rule.validate(5)

    def test_failing_validator(self):
        """Test failing custom validator."""
        rule = Custom(lambda x: x > 0, "must be positive")
        with pytest.raises(ValidationError):
            rule.validate(-5)


# =============================================================================
# Composite Rule Tests
# =============================================================================

class TestCompositeRules:
    """Tests for composite rules (All, Any_)."""

    def test_all_pass(self):
        """Test All rule when all pass."""
        rule = All(Required(), TypeOf(str), Length(min_len=3))
        rule.validate("hello")

    def test_all_fail(self):
        """Test All rule when one fails."""
        rule = All(Required(), TypeOf(str), Length(min_len=10))
        with pytest.raises(ValidationError):
            rule.validate("hello")

    def test_any_one_passes(self):
        """Test Any_ rule when one passes."""
        rule = Any_(TypeOf(str), TypeOf(int))
        rule.validate("hello")
        rule.validate(123)

    def test_any_none_passes(self):
        """Test Any_ rule when none pass."""
        rule = Any_(TypeOf(str), TypeOf(int))
        with pytest.raises(ValidationError):
            rule.validate([1, 2, 3])


# =============================================================================
# TypeCoercer Tests
# =============================================================================

class TestTypeCoercer:
    """Tests for TypeCoercer."""

    def test_to_string(self):
        """Test coercion to string."""
        coercer = TypeCoercer()
        assert coercer.coerce(123, str) == "123"
        assert coercer.coerce(b"bytes", str) == "bytes"

    def test_to_int(self):
        """Test coercion to int."""
        coercer = TypeCoercer()
        assert coercer.coerce("123", int) == 123
        assert coercer.coerce("3.14", int) == 3
        assert coercer.coerce(True, int) == 1

    def test_to_float(self):
        """Test coercion to float."""
        coercer = TypeCoercer()
        assert coercer.coerce("3.14", float) == 3.14
        assert coercer.coerce(True, float) == 1.0

    def test_to_bool(self):
        """Test coercion to bool."""
        coercer = TypeCoercer()
        assert coercer.coerce("true", bool) is True
        assert coercer.coerce("yes", bool) is True
        assert coercer.coerce("1", bool) is True
        assert coercer.coerce("false", bool) is False
        assert coercer.coerce("no", bool) is False
        assert coercer.coerce("0", bool) is False

    def test_to_bool_invalid(self):
        """Test invalid bool coercion."""
        coercer = TypeCoercer()
        with pytest.raises(CoercionError):
            coercer.coerce("maybe", bool)

    def test_to_datetime(self):
        """Test coercion to datetime."""
        coercer = TypeCoercer()
        result = coercer.coerce("2024-01-15", datetime)
        assert result.year == 2024
        assert result.month == 1
        assert result.day == 15

    def test_to_date(self):
        """Test coercion to date."""
        coercer = TypeCoercer()
        result = coercer.coerce("2024-01-15", date)
        assert result.year == 2024

    def test_to_list(self):
        """Test coercion to list."""
        coercer = TypeCoercer()
        assert coercer.coerce("a,b,c", list) == ["a", "b", "c"]
        assert coercer.coerce('["a", "b"]', list) == ["a", "b"]
        assert coercer.coerce((1, 2, 3), list) == [1, 2, 3]

    def test_to_dict(self):
        """Test coercion to dict."""
        coercer = TypeCoercer()
        assert coercer.coerce('{"key": "value"}', dict) == {"key": "value"}

    def test_to_uuid(self):
        """Test coercion to UUID."""
        coercer = TypeCoercer()
        result = coercer.coerce("550e8400-e29b-41d4-a716-446655440000", UUID)
        assert isinstance(result, UUID)

    def test_strict_mode(self):
        """Test strict mode prevents coercion."""
        coercer = TypeCoercer(strict=True)
        with pytest.raises(CoercionError):
            coercer.coerce("123", int)

    def test_none_passthrough(self):
        """Test None passes through."""
        coercer = TypeCoercer()
        assert coercer.coerce(None, str) is None


# =============================================================================
# FieldSpec Tests
# =============================================================================

class TestFieldSpec:
    """Tests for FieldSpec."""

    def test_basic_validation(self):
        """Test basic field validation."""
        spec = FieldSpec(name="email", rules=[Email()])
        value, errors = spec.validate("user@example.com")
        assert len(errors) == 0
        assert value == "user@example.com"

    def test_validation_failure(self):
        """Test field validation failure."""
        spec = FieldSpec(name="email", rules=[Email()])
        value, errors = spec.validate("invalid")
        assert len(errors) == 1

    def test_nullable(self):
        """Test nullable field."""
        spec = FieldSpec(name="optional", nullable=True)
        value, errors = spec.validate(None)
        assert len(errors) == 0

    def test_not_nullable(self):
        """Test non-nullable field."""
        spec = FieldSpec(name="required", nullable=False)
        value, errors = spec.validate(None)
        assert len(errors) == 1

    def test_default_value(self):
        """Test default value."""
        spec = FieldSpec(name="status", default="pending")
        value, errors = spec.validate(None)
        assert value == "pending"

    def test_coercion(self):
        """Test field with coercion."""
        spec = FieldSpec(name="count", type=int, coerce=True)
        coercer = TypeCoercer()
        value, errors = spec.validate("42", coercer)
        assert value == 42
        assert len(errors) == 0


# =============================================================================
# Schema Tests
# =============================================================================

class TestSchema:
    """Tests for Schema."""

    def test_basic_validation(self):
        """Test basic schema validation."""
        schema = Schema()
        schema.field("name", str, rules=[Required()])
        schema.field("age", int, rules=[Range(0, 150)])

        result = schema.validate({"name": "John", "age": 30}, raise_on_error=False)
        assert result.is_valid
        assert result.data["name"] == "John"
        assert result.data["age"] == 30

    def test_validation_failure(self):
        """Test schema validation failure."""
        schema = Schema()
        schema.field("name", str, rules=[Required()])

        result = schema.validate({"name": ""}, raise_on_error=False)
        assert not result.is_valid

    def test_raise_on_error(self):
        """Test raising on validation error."""
        schema = Schema()
        schema.field("name", str, rules=[Required()])

        with pytest.raises(ValidationError):
            schema.validate({"name": ""})

    def test_strict_mode(self):
        """Test strict mode rejects unknown fields."""
        schema = Schema(strict=True)
        schema.field("name", str)

        result = schema.validate({"name": "John", "extra": "field"}, raise_on_error=False)
        assert not result.is_valid

    def test_coerce_mode(self):
        """Test schema-level coercion."""
        schema = Schema(coerce=True)
        schema.field("count", int)

        result = schema.validate({"count": "42"}, raise_on_error=False)
        assert result.is_valid
        assert result.data["count"] == 42

    def test_alias(self):
        """Test field alias."""
        schema = Schema()
        schema.add_field(FieldSpec(name="user_name", alias="username"))

        result = schema.validate({"username": "john"}, raise_on_error=False)
        assert result.data["user_name"] == "john"

    def test_fluent_api(self):
        """Test fluent field addition."""
        schema = (
            Schema()
            .field("name", str, rules=[Required()])
            .field("age", int, rules=[Range(0, 150)])
        )

        result = schema.validate({"name": "John", "age": 30}, raise_on_error=False)
        assert result.is_valid

    def test_to_dict(self):
        """Test schema serialization."""
        schema = Schema()
        schema.field("name", str, description="User name")

        exported = schema.to_dict()
        assert "fields" in exported
        assert "name" in exported["fields"]

    def test_non_dict_input(self):
        """Test that non-dict input fails."""
        schema = Schema()
        schema.field("name", str)

        result = schema.validate("not a dict", raise_on_error=False)
        assert not result.is_valid


# =============================================================================
# DataContract Tests
# =============================================================================

class TestDataContract:
    """Tests for DataContract."""

    def test_contract_validation(self):
        """Test contract validation."""
        schema = Schema()
        schema.field("id", str, rules=[Required()])
        schema.field("value", int)

        contract = DataContract(
            name="test_contract",
            version="1.0.0",
            schema=schema
        )

        result = contract.validate({"id": "abc", "value": 42})
        assert result.is_valid

    def test_contract_enforce(self):
        """Test contract enforcement."""
        schema = Schema()
        schema.field("id", str, rules=[Required()])

        contract = DataContract(
            name="test_contract",
            version="1.0.0",
            schema=schema
        )

        data = contract.enforce({"id": "abc"})
        assert data["id"] == "abc"

    def test_contract_violation(self):
        """Test contract violation."""
        schema = Schema()
        schema.field("id", str, rules=[Required()])

        contract = DataContract(
            name="test_contract",
            version="1.0.0",
            schema=schema
        )

        with pytest.raises(ContractViolation):
            contract.enforce({"id": ""})

    def test_contract_fingerprint(self):
        """Test contract fingerprint generation."""
        schema = Schema()
        schema.field("id", str)

        contract = DataContract(
            name="test",
            version="1.0.0",
            schema=schema
        )

        fp = contract.fingerprint()
        assert len(fp) == 16
        assert fp == contract.fingerprint()  # Deterministic

    def test_contract_compatibility(self):
        """Test contract compatibility check."""
        schema1 = Schema()
        schema1.field("id", str)
        schema1.field("name", str)

        schema2 = Schema()
        schema2.field("id", str)
        schema2.field("name", str)
        schema2.field("extra", str)  # Added field

        contract1 = DataContract("test", "1.0.0", schema1)
        contract2 = DataContract("test", "2.0.0", schema2)

        assert contract1.is_compatible(contract2)


# =============================================================================
# ContractRegistry Tests
# =============================================================================

class TestContractRegistry:
    """Tests for ContractRegistry."""

    def test_register_and_get(self):
        """Test registering and retrieving contracts."""
        registry = ContractRegistry()

        schema = Schema()
        schema.field("id", str)

        contract = DataContract("test", "1.0.0", schema)
        registry.register(contract)

        retrieved = registry.get("test", "1.0.0")
        assert retrieved is not None
        assert retrieved.name == "test"

    def test_get_latest(self):
        """Test getting latest version."""
        registry = ContractRegistry()

        schema = Schema()
        schema.field("id", str)

        registry.register(DataContract("test", "1.0.0", schema))
        registry.register(DataContract("test", "2.0.0", schema))

        latest = registry.get("test")
        assert latest.version == "2.0.0"

    def test_get_nonexistent(self):
        """Test getting nonexistent contract."""
        registry = ContractRegistry()
        assert registry.get("nonexistent") is None

    def test_list_contracts(self):
        """Test listing contracts."""
        registry = ContractRegistry()

        schema = Schema()
        registry.register(DataContract("contract_a", "1.0.0", schema))
        registry.register(DataContract("contract_b", "1.0.0", schema))

        contracts = registry.list_contracts()
        assert len(contracts) == 2
        assert ("contract_a", "1.0.0") in contracts

    def test_validate_via_registry(self):
        """Test validation through registry."""
        registry = ContractRegistry()

        schema = Schema()
        schema.field("id", str, rules=[Required()])

        registry.register(DataContract("test", "1.0.0", schema))

        result = registry.validate("test", {"id": "abc"})
        assert result.is_valid

    def test_validate_unknown_contract(self):
        """Test validation of unknown contract."""
        registry = ContractRegistry()
        result = registry.validate("unknown", {})
        assert not result.is_valid


# =============================================================================
# SecurityValidators Tests
# =============================================================================

class TestSecurityValidators:
    """Tests for SecurityValidators."""

    def test_ipv4(self):
        """Test IPv4 validator."""
        rule = SecurityValidators.ipv4()
        rule.validate("192.168.1.1")
        with pytest.raises(ValidationError):
            rule.validate("::1")

    def test_ipv6(self):
        """Test IPv6 validator."""
        rule = SecurityValidators.ipv6()
        rule.validate("::1")
        with pytest.raises(ValidationError):
            rule.validate("192.168.1.1")

    def test_mac_address(self):
        """Test MAC address validator."""
        rule = SecurityValidators.mac_address()
        rule.validate("00:1A:2B:3C:4D:5E")
        rule.validate("00-1A-2B-3C-4D-5E")
        with pytest.raises(ValidationError):
            rule.validate("invalid")

    def test_hostname(self):
        """Test hostname validator."""
        rule = SecurityValidators.hostname()
        rule.validate("example.com")
        rule.validate("sub.example.com")
        rule.validate("localhost")

    def test_port(self):
        """Test port validator."""
        rule = SecurityValidators.port()
        rule.validate(80)
        rule.validate(443)
        with pytest.raises(ValidationError):
            rule.validate(0)
        with pytest.raises(ValidationError):
            rule.validate(70000)

    def test_md5_hash(self):
        """Test MD5 hash validator."""
        rule = SecurityValidators.md5_hash()
        rule.validate("d41d8cd98f00b204e9800998ecf8427e")
        with pytest.raises(ValidationError):
            rule.validate("invalid")

    def test_sha1_hash(self):
        """Test SHA1 hash validator."""
        rule = SecurityValidators.sha1_hash()
        rule.validate("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        with pytest.raises(ValidationError):
            rule.validate("invalid")

    def test_sha256_hash(self):
        """Test SHA256 hash validator."""
        rule = SecurityValidators.sha256_hash()
        rule.validate("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        with pytest.raises(ValidationError):
            rule.validate("invalid")

    def test_cve_id(self):
        """Test CVE ID validator."""
        rule = SecurityValidators.cve_id()
        rule.validate("CVE-2024-12345")
        rule.validate("CVE-2024-1234")
        with pytest.raises(ValidationError):
            rule.validate("CVE-24-123")

    def test_severity(self):
        """Test severity validator."""
        rule = SecurityValidators.severity()
        rule.validate("critical")
        rule.validate("HIGH")  # Case insensitive
        with pytest.raises(ValidationError):
            rule.validate("severe")

    def test_cvss_score(self):
        """Test CVSS score validator."""
        rule = SecurityValidators.cvss_score()
        rule.validate(7.5)
        rule.validate(0.0)
        rule.validate(10.0)
        with pytest.raises(ValidationError):
            rule.validate(10.1)

    def test_mitre_technique(self):
        """Test MITRE ATT&CK technique validator."""
        rule = SecurityValidators.mitre_technique()
        rule.validate("T1059")
        rule.validate("T1059.001")
        with pytest.raises(ValidationError):
            rule.validate("T59")

    def test_base64_data(self):
        """Test Base64 validator."""
        rule = SecurityValidators.base64_data()
        rule.validate("SGVsbG8gV29ybGQ=")
        rule.validate("YWJj")


# =============================================================================
# Utility Function Tests
# =============================================================================

class TestUtilityFunctions:
    """Tests for utility functions."""

    def test_validate_dict(self):
        """Test validate_dict function."""
        schema = Schema()
        schema.field("name", str, rules=[Required()])

        result = validate_dict({"name": "John"}, schema)
        assert result.is_valid

    def test_validate_list(self):
        """Test validate_list function."""
        schema = Schema()
        schema.field("id", int)

        items = [{"id": 1}, {"id": 2}, {"id": 3}]
        results = validate_list(items, schema)

        assert len(results) == 3
        assert all(r.is_valid for r in results)

    def test_create_schema(self):
        """Test create_schema function."""
        schema = create_schema(
            name=(str, Required()),
            age=(int, Range(0, 150)),
            email=(str, Email())
        )

        result = schema.validate({
            "name": "John",
            "age": 30,
            "email": "john@example.com"
        }, raise_on_error=False)

        assert result.is_valid


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for data validation."""

    def test_security_event_schema(self):
        """Test complex security event schema."""
        schema = (
            Schema(coerce=True)
            .field("event_id", str, rules=[Required(), UUID4()])
            .field("timestamp", datetime)
            .field("severity", str, rules=[SecurityValidators.severity()])
            .field("source_ip", str, rules=[IPAddress()])
            .field("destination_ip", str, rules=[IPAddress()], nullable=True)
            .field("port", int, rules=[SecurityValidators.port()], nullable=True)
            .field("description", str, rules=[Length(max_len=1000)])
        )

        event = {
            "event_id": "550e8400-e29b-41d4-a716-446655440000",
            "timestamp": "2024-01-15T10:30:00",
            "severity": "high",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "port": 443,
            "description": "Suspicious connection attempt"
        }

        result = schema.validate(event, raise_on_error=False)
        assert result.is_valid
        assert isinstance(result.data["timestamp"], datetime)

    def test_vulnerability_contract(self):
        """Test vulnerability data contract."""
        schema = Schema()
        schema.field("cve_id", str, rules=[Required(), SecurityValidators.cve_id()])
        schema.field("cvss_score", float, rules=[SecurityValidators.cvss_score()])
        schema.field("severity", str, rules=[SecurityValidators.severity()])
        schema.field("affected_systems", list, rules=[Required()])
        schema.field("description", str)

        contract = DataContract(
            name="vulnerability",
            version="1.0.0",
            schema=schema,
            producer="scanner",
            consumer="dashboard"
        )

        vuln = {
            "cve_id": "CVE-2024-12345",
            "cvss_score": 8.5,
            "severity": "high",
            "affected_systems": ["server-1", "server-2"],
            "description": "Remote code execution vulnerability"
        }

        validated = contract.enforce(vuln)
        assert validated["cve_id"] == "CVE-2024-12345"

    def test_full_contract_workflow(self):
        """Test complete contract registration and validation workflow."""
        registry = ContractRegistry()

        # V1 schema
        schema_v1 = Schema()
        schema_v1.field("id", str, rules=[Required()])
        schema_v1.field("name", str, rules=[Required()])

        contract_v1 = DataContract("user", "1.0.0", schema_v1)
        registry.register(contract_v1)

        # V2 schema (backward compatible - adds optional field)
        schema_v2 = Schema()
        schema_v2.field("id", str, rules=[Required()])
        schema_v2.field("name", str, rules=[Required()])
        schema_v2.field("email", str, rules=[Email()], nullable=True)

        contract_v2 = DataContract("user", "2.0.0", schema_v2)
        registry.register(contract_v2)

        # Check compatibility
        assert contract_v1.is_compatible(contract_v2)

        # Validate with latest version
        result = registry.validate("user", {"id": "1", "name": "John"})
        assert result.is_valid

        # Validate with specific version
        result = registry.validate(
            "user",
            {"id": "1", "name": "John", "email": "john@example.com"},
            version="2.0.0"
        )
        assert result.is_valid
