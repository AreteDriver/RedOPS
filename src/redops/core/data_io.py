"""
Data Import/Export Module for RedOPS.
Provides STIX/TAXII, CSV, JSON Lines, and bulk operations
for threat intelligence data exchange.
"""

import csv
import gzip
import json
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    BinaryIO,
    Callable,
    Generator,
    Iterator,
    TextIO,
    Type,
)


class DataFormat(Enum):
    """Supported data formats."""

    JSON = "json"
    JSONL = "jsonl"
    CSV = "csv"
    STIX = "stix"
    XML = "xml"


class ImportError(Exception):
    """Error during data import."""

    def __init__(
        self, message: str, line: int | None = None, details: dict | None = None
    ):
        super().__init__(message)
        self.line = line
        self.details = details or {}


class ExportError(Exception):
    """Error during data export."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.details = details or {}


class ValidationError(Exception):
    """Error during data validation."""

    def __init__(self, message: str, field: str | None = None, value: Any = None):
        super().__init__(message)
        self.field = field
        self.value = value


@dataclass
class ImportResult:
    """Result of an import operation."""

    total_records: int = 0
    successful: int = 0
    failed: int = 0
    skipped: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_records == 0:
            return 0.0
        return self.successful / self.total_records

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_records": self.total_records,
            "successful": self.successful,
            "failed": self.failed,
            "skipped": self.skipped,
            "success_rate": self.success_rate,
            "duration_seconds": self.duration_seconds,
            "errors": self.errors[:10],  # Limit errors in output
            "warnings": self.warnings[:10],
        }


@dataclass
class ExportResult:
    """Result of an export operation."""

    total_records: int = 0
    exported: int = 0
    failed: int = 0
    file_path: str | None = None
    file_size_bytes: int = 0
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_records": self.total_records,
            "exported": self.exported,
            "failed": self.failed,
            "file_path": self.file_path,
            "file_size_bytes": self.file_size_bytes,
            "duration_seconds": self.duration_seconds,
        }


@dataclass
class FieldMapping:
    """Mapping between source and target field names."""

    source: str
    target: str
    transform: Callable[[Any], Any] | None = None
    default: Any = None
    required: bool = False


class DataValidator:
    """Validates data records."""

    def __init__(self):
        """Initialize validator."""
        self._rules: dict[str, list[Callable[[Any], bool]]] = {}
        self._required_fields: list[str] = []
        self._field_types: dict[str, Type] = {}

    def require(self, *fields: str) -> "DataValidator":
        """Mark fields as required."""
        self._required_fields.extend(fields)
        return self

    def add_rule(
        self, field: str, rule: Callable[[Any], bool], message: str = ""
    ) -> "DataValidator":
        """Add validation rule for a field."""
        if field not in self._rules:
            self._rules[field] = []
        self._rules[field].append((rule, message))
        return self

    def expect_type(self, field: str, field_type: Type) -> "DataValidator":
        """Expect a specific type for a field."""
        self._field_types[field] = field_type
        return self

    def validate(self, record: dict[str, Any]) -> list[ValidationError]:
        """Validate a record and return list of errors."""
        errors = []
        # Check required fields
        for field_name in self._required_fields:
            if field_name not in record or record[field_name] is None:
                errors.append(
                    ValidationError(f"Missing required field: {field_name}", field_name)
                )
        # Check field types
        for field_name, expected_type in self._field_types.items():
            if field_name in record and record[field_name] is not None:
                if not isinstance(record[field_name], expected_type):
                    errors.append(
                        ValidationError(
                            f"Invalid type for {field_name}: expected {expected_type.__name__}",
                            field_name,
                            record[field_name],
                        )
                    )
        # Check custom rules
        for field_name, rules in self._rules.items():
            if field_name in record:
                for rule, message in rules:
                    try:
                        if not rule(record[field_name]):
                            errors.append(
                                ValidationError(
                                    message or f"Validation failed for {field_name}",
                                    field_name,
                                    record[field_name],
                                )
                            )
                    except Exception as e:
                        errors.append(
                            ValidationError(
                                f"Validation error for {field_name}: {e}",
                                field_name,
                                record[field_name],
                            )
                        )
        return errors

    def is_valid(self, record: dict[str, Any]) -> bool:
        """Check if record is valid."""
        return len(self.validate(record)) == 0


class DataTransformer:
    """Transforms data records."""

    def __init__(self, mappings: list[FieldMapping] | None = None):
        """Initialize transformer."""
        self._mappings = mappings or []
        self._transforms: list[Callable[[dict], dict]] = []

    def add_mapping(self, mapping: FieldMapping) -> "DataTransformer":
        """Add a field mapping."""
        self._mappings.append(mapping)
        return self

    def map_field(
        self,
        source: str,
        target: str,
        transform: Callable[[Any], Any] | None = None,
        default: Any = None,
    ) -> "DataTransformer":
        """Add a simple field mapping."""
        self._mappings.append(
            FieldMapping(
                source=source,
                target=target,
                transform=transform,
                default=default,
            )
        )
        return self

    def add_transform(self, transform: Callable[[dict], dict]) -> "DataTransformer":
        """Add a record-level transform."""
        self._transforms.append(transform)
        return self

    def transform(self, record: dict[str, Any]) -> dict[str, Any]:
        """Transform a record."""
        result = {}
        # Apply field mappings
        for mapping in self._mappings:
            value = self._get_nested(record, mapping.source)
            if value is None:
                value = mapping.default
            if value is not None and mapping.transform:
                value = mapping.transform(value)
            if value is not None:
                self._set_nested(result, mapping.target, value)
        # Apply record-level transforms
        for transform in self._transforms:
            result = transform(result)
        return result

    def _get_nested(self, data: dict, path: str) -> Any:
        """Get nested value from dict."""
        parts = path.split(".")
        current = data
        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current

    def _set_nested(self, data: dict, path: str, value: Any) -> None:
        """Set nested value in dict."""
        parts = path.split(".")
        current = data
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        current[parts[-1]] = value


class DataImporter(ABC):
    """Base class for data importers."""

    def __init__(
        self,
        validator: DataValidator | None = None,
        transformer: DataTransformer | None = None,
        on_record: Callable[[dict], None] | None = None,
        on_error: Callable[[Exception, dict], None] | None = None,
        skip_invalid: bool = True,
    ):
        """Initialize importer."""
        self._validator = validator
        self._transformer = transformer
        self._on_record = on_record
        self._on_error = on_error
        self._skip_invalid = skip_invalid

    @abstractmethod
    def import_file(self, path: str | Path) -> ImportResult:
        """Import data from a file."""
        pass

    @abstractmethod
    def import_stream(self, stream: TextIO | BinaryIO) -> ImportResult:
        """Import data from a stream."""
        pass

    def _process_record(
        self, record: dict[str, Any], result: ImportResult
    ) -> dict | None:
        """Process a single record."""
        result.total_records += 1
        # Validate
        if self._validator:
            errors = self._validator.validate(record)
            if errors:
                result.failed += 1
                for error in errors:
                    result.errors.append(
                        {
                            "record": result.total_records,
                            "field": error.field,
                            "message": str(error),
                        }
                    )
                if self._skip_invalid:
                    result.skipped += 1
                    return None
                if self._on_error:
                    self._on_error(errors[0], record)
        # Transform
        if self._transformer:
            record = self._transformer.transform(record)
        # Callback
        if self._on_record:
            self._on_record(record)
        result.successful += 1
        return record


class JSONImporter(DataImporter):
    """Imports JSON data."""

    def import_file(self, path: str | Path) -> ImportResult:
        """Import from JSON file."""
        path = Path(path)
        with open(path, "r", encoding="utf-8") as f:
            return self.import_stream(f)

    def import_stream(self, stream: TextIO) -> ImportResult:
        """Import from JSON stream."""
        import time

        start = time.time()
        result = ImportResult()
        try:
            data = json.load(stream)
            if isinstance(data, list):
                for record in data:
                    self._process_record(record, result)
            elif isinstance(data, dict):
                self._process_record(data, result)
            else:
                raise ImportError("Invalid JSON structure: expected array or object")
        except json.JSONDecodeError as e:
            raise ImportError(f"JSON parse error: {e}")
        result.duration_seconds = time.time() - start
        return result


class JSONLImporter(DataImporter):
    """Imports JSON Lines data."""

    def import_file(self, path: str | Path) -> ImportResult:
        """Import from JSONL file."""
        path = Path(path)
        # Handle gzipped files
        if str(path).endswith(".gz"):
            with gzip.open(path, "rt", encoding="utf-8") as f:
                return self.import_stream(f)
        else:
            with open(path, "r", encoding="utf-8") as f:
                return self.import_stream(f)

    def import_stream(self, stream: TextIO) -> ImportResult:
        """Import from JSONL stream."""
        import time

        start = time.time()
        result = ImportResult()
        for line_num, line in enumerate(stream, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                self._process_record(record, result)
            except json.JSONDecodeError as e:
                result.failed += 1
                result.errors.append(
                    {
                        "line": line_num,
                        "message": f"JSON parse error: {e}",
                    }
                )
        result.duration_seconds = time.time() - start
        return result

    def iter_records(self, path: str | Path) -> Generator[dict, None, None]:
        """Iterate over records without loading all into memory."""
        path = Path(path)
        if str(path).endswith(".gz"):

            def opener():
                return gzip.open(path, "rt", encoding="utf-8")
        else:

            def opener():
                return open(path, "r", encoding="utf-8")

        with opener() as f:
            for line in f:
                line = line.strip()
                if line:
                    yield json.loads(line)


class CSVImporter(DataImporter):
    """Imports CSV data."""

    def __init__(
        self,
        delimiter: str = ",",
        quotechar: str = '"',
        has_header: bool = True,
        fieldnames: list[str] | None = None,
        **kwargs,
    ):
        """Initialize CSV importer."""
        super().__init__(**kwargs)
        self._delimiter = delimiter
        self._quotechar = quotechar
        self._has_header = has_header
        self._fieldnames = fieldnames

    def import_file(self, path: str | Path) -> ImportResult:
        """Import from CSV file."""
        path = Path(path)
        with open(path, "r", encoding="utf-8", newline="") as f:
            return self.import_stream(f)

    def import_stream(self, stream: TextIO) -> ImportResult:
        """Import from CSV stream."""
        import time

        start = time.time()
        result = ImportResult()
        if self._has_header:
            reader = csv.DictReader(
                stream,
                delimiter=self._delimiter,
                quotechar=self._quotechar,
            )
        else:
            reader = csv.DictReader(
                stream,
                fieldnames=self._fieldnames,
                delimiter=self._delimiter,
                quotechar=self._quotechar,
            )
        for row in reader:
            # Convert empty strings to None
            record = {k: (v if v != "" else None) for k, v in row.items()}
            self._process_record(record, result)
        result.duration_seconds = time.time() - start
        return result


class STIXImporter(DataImporter):
    """Imports STIX 2.1 data."""

    STIX_TYPES = {
        "indicator",
        "malware",
        "threat-actor",
        "attack-pattern",
        "campaign",
        "intrusion-set",
        "tool",
        "vulnerability",
        "identity",
        "location",
        "infrastructure",
        "observed-data",
        "report",
        "grouping",
        "note",
        "opinion",
    }

    def import_file(self, path: str | Path) -> ImportResult:
        """Import from STIX file."""
        path = Path(path)
        with open(path, "r", encoding="utf-8") as f:
            return self.import_stream(f)

    def import_stream(self, stream: TextIO) -> ImportResult:
        """Import from STIX stream."""
        import time

        start = time.time()
        result = ImportResult()
        try:
            data = json.load(stream)
            # Handle STIX Bundle or array
            if isinstance(data, list):
                objects = data
            elif isinstance(data, dict) and data.get("type") == "bundle":
                objects = data.get("objects", [])
            elif isinstance(data, dict):
                objects = [data]
            else:
                objects = []
            for obj in objects:
                if self._is_stix_object(obj):
                    self._process_record(obj, result)
                else:
                    result.skipped += 1
                    result.warnings.append(
                        f"Skipped non-STIX object: {obj.get('type', 'unknown')}"
                    )
        except json.JSONDecodeError as e:
            raise ImportError(f"STIX JSON parse error: {e}")
        result.duration_seconds = time.time() - start
        return result

    def _is_stix_object(self, obj: dict) -> bool:
        """Check if object is a valid STIX object."""
        if not isinstance(obj, dict):
            return False
        obj_type = obj.get("type", "")
        # Check domain objects and relationship
        if obj_type in self.STIX_TYPES:
            return True
        if obj_type == "relationship":
            return True
        if obj_type == "sighting":
            return True
        return False


class DataExporter(ABC):
    """Base class for data exporters."""

    def __init__(
        self, transformer: DataTransformer | None = None, compress: bool = False
    ):
        """Initialize exporter."""
        self._transformer = transformer
        self._compress = compress

    @abstractmethod
    def export_file(self, records: list[dict], path: str | Path) -> ExportResult:
        """Export data to a file."""
        pass

    @abstractmethod
    def export_stream(
        self, records: Iterator[dict], stream: TextIO | BinaryIO
    ) -> ExportResult:
        """Export data to a stream."""
        pass

    def _transform_record(self, record: dict) -> dict:
        """Transform a record before export."""
        if self._transformer:
            return self._transformer.transform(record)
        return record


class JSONExporter(DataExporter):
    """Exports JSON data."""

    def __init__(self, pretty: bool = False, **kwargs):
        """Initialize JSON exporter."""
        super().__init__(**kwargs)
        self._pretty = pretty

    def export_file(self, records: list[dict], path: str | Path) -> ExportResult:
        """Export to JSON file."""
        import time

        start = time.time()
        result = ExportResult()
        path = Path(path)
        transformed = []
        for record in records:
            transformed.append(self._transform_record(record))
            result.exported += 1
        result.total_records = len(records)
        if self._compress:
            path = Path(str(path) + ".gz") if not str(path).endswith(".gz") else path
            with gzip.open(path, "wt", encoding="utf-8") as f:
                json.dump(
                    transformed, f, indent=2 if self._pretty else None, default=str
                )
        else:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(
                    transformed, f, indent=2 if self._pretty else None, default=str
                )
        result.file_path = str(path)
        result.file_size_bytes = path.stat().st_size
        result.duration_seconds = time.time() - start
        return result

    def export_stream(self, records: Iterator[dict], stream: TextIO) -> ExportResult:
        """Export to JSON stream."""
        import time

        start = time.time()
        result = ExportResult()
        all_records = []
        for record in records:
            all_records.append(self._transform_record(record))
            result.exported += 1
        result.total_records = result.exported
        json.dump(all_records, stream, indent=2 if self._pretty else None, default=str)
        result.duration_seconds = time.time() - start
        return result


class JSONLExporter(DataExporter):
    """Exports JSON Lines data."""

    def export_file(self, records: list[dict], path: str | Path) -> ExportResult:
        """Export to JSONL file."""
        import time

        start = time.time()
        result = ExportResult()
        path = Path(path)
        if self._compress:
            path = Path(str(path) + ".gz") if not str(path).endswith(".gz") else path

            def opener():
                return gzip.open(path, "wt", encoding="utf-8")
        else:

            def opener():
                return open(path, "w", encoding="utf-8")

        with opener() as f:
            for record in records:
                transformed = self._transform_record(record)
                f.write(json.dumps(transformed, default=str) + "\n")
                result.exported += 1
        result.total_records = len(records)
        result.file_path = str(path)
        result.file_size_bytes = path.stat().st_size
        result.duration_seconds = time.time() - start
        return result

    def export_stream(self, records: Iterator[dict], stream: TextIO) -> ExportResult:
        """Export to JSONL stream."""
        import time

        start = time.time()
        result = ExportResult()
        for record in records:
            transformed = self._transform_record(record)
            stream.write(json.dumps(transformed, default=str) + "\n")
            result.exported += 1
        result.total_records = result.exported
        result.duration_seconds = time.time() - start
        return result


class CSVExporter(DataExporter):
    """Exports CSV data."""

    def __init__(
        self,
        delimiter: str = ",",
        quotechar: str = '"',
        fieldnames: list[str] | None = None,
        **kwargs,
    ):
        """Initialize CSV exporter."""
        super().__init__(**kwargs)
        self._delimiter = delimiter
        self._quotechar = quotechar
        self._fieldnames = fieldnames

    def export_file(self, records: list[dict], path: str | Path) -> ExportResult:
        """Export to CSV file."""
        import time

        start = time.time()
        result = ExportResult()
        path = Path(path)
        if not records:
            result.file_path = str(path)
            return result
        # Transform all records first
        transformed = [self._transform_record(r) for r in records]
        # Determine fieldnames
        fieldnames = self._fieldnames
        if not fieldnames:
            fieldnames = list(transformed[0].keys())
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=fieldnames,
                delimiter=self._delimiter,
                quotechar=self._quotechar,
                extrasaction="ignore",
            )
            writer.writeheader()
            for record in transformed:
                writer.writerow(record)
                result.exported += 1
        result.total_records = len(records)
        result.file_path = str(path)
        result.file_size_bytes = path.stat().st_size
        result.duration_seconds = time.time() - start
        return result

    def export_stream(self, records: Iterator[dict], stream: TextIO) -> ExportResult:
        """Export to CSV stream."""
        import time

        start = time.time()
        result = ExportResult()
        first = True
        writer = None
        for record in records:
            transformed = self._transform_record(record)
            if first:
                fieldnames = self._fieldnames or list(transformed.keys())
                writer = csv.DictWriter(
                    stream,
                    fieldnames=fieldnames,
                    delimiter=self._delimiter,
                    quotechar=self._quotechar,
                    extrasaction="ignore",
                )
                writer.writeheader()
                first = False
            writer.writerow(transformed)
            result.exported += 1
        result.total_records = result.exported
        result.duration_seconds = time.time() - start
        return result


class STIXExporter(DataExporter):
    """Exports STIX 2.1 data."""

    def __init__(
        self,
        bundle_id: str | None = None,
        created_by: str | None = None,
        **kwargs,
    ):
        """Initialize STIX exporter."""
        super().__init__(**kwargs)
        self._bundle_id = bundle_id
        self._created_by = created_by

    def export_file(self, records: list[dict], path: str | Path) -> ExportResult:
        """Export to STIX file."""
        import time

        start = time.time()
        result = ExportResult()
        path = Path(path)
        # Create STIX bundle
        bundle = self._create_bundle(records, result)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2, default=str)
        result.file_path = str(path)
        result.file_size_bytes = path.stat().st_size
        result.duration_seconds = time.time() - start
        return result

    def export_stream(self, records: Iterator[dict], stream: TextIO) -> ExportResult:
        """Export to STIX stream."""
        import time

        start = time.time()
        result = ExportResult()
        records_list = list(records)
        bundle = self._create_bundle(records_list, result)
        json.dump(bundle, stream, indent=2, default=str)
        result.duration_seconds = time.time() - start
        return result

    def _create_bundle(self, records: list[dict], result: ExportResult) -> dict:
        """Create STIX bundle from records."""
        objects = []
        for record in records:
            transformed = self._transform_record(record)
            # Ensure required STIX fields
            if "type" not in transformed:
                result.failed += 1
                continue
            if "id" not in transformed:
                transformed["id"] = f"{transformed['type']}--{uuid.uuid4()}"
            if "spec_version" not in transformed:
                transformed["spec_version"] = "2.1"
            objects.append(transformed)
            result.exported += 1
        result.total_records = len(records)
        return {
            "type": "bundle",
            "id": self._bundle_id or f"bundle--{uuid.uuid4()}",
            "objects": objects,
        }


class BulkProcessor:
    """Processes data in bulk with batching."""

    def __init__(
        self,
        batch_size: int = 1000,
        on_batch: Callable[[list[dict]], None] | None = None,
        on_progress: Callable[[int, int], None] | None = None,
    ):
        """Initialize bulk processor."""
        self._batch_size = batch_size
        self._on_batch = on_batch
        self._on_progress = on_progress

    def process(self, records: Iterator[dict], total: int | None = None) -> int:
        """Process records in batches."""
        batch = []
        processed = 0
        for record in records:
            batch.append(record)
            if len(batch) >= self._batch_size:
                if self._on_batch:
                    self._on_batch(batch)
                processed += len(batch)
                if self._on_progress and total:
                    self._on_progress(processed, total)
                batch = []
        # Process remaining
        if batch:
            if self._on_batch:
                self._on_batch(batch)
            processed += len(batch)
            if self._on_progress and total:
                self._on_progress(processed, total)
        return processed

    def process_file(
        self, path: str | Path, format: DataFormat = DataFormat.JSONL
    ) -> int:
        """Process records from a file."""
        path = Path(path)
        if format == DataFormat.JSONL:
            importer = JSONLImporter()
            return self.process(importer.iter_records(path))
        else:
            raise ValueError(f"Streaming not supported for format: {format}")


class FormatConverter:
    """Converts between data formats."""

    def __init__(self, transformer: DataTransformer | None = None):
        """Initialize converter."""
        self._transformer = transformer

    def convert(
        self,
        input_path: str | Path,
        output_path: str | Path,
        input_format: DataFormat,
        output_format: DataFormat,
    ) -> tuple[ImportResult, ExportResult]:
        """Convert file from one format to another."""
        # Get importer
        importer = self._get_importer(input_format)
        # Import data
        import_result = importer.import_file(input_path)
        # Collect records (we need to re-import since importer doesn't store)
        records = []

        def collect(record):
            records.append(record)

        collector = self._get_importer(input_format)
        collector._on_record = collect
        collector.import_file(input_path)
        # Get exporter
        exporter = self._get_exporter(output_format)
        # Export data
        export_result = exporter.export_file(records, output_path)
        return import_result, export_result

    def _get_importer(self, format: DataFormat) -> DataImporter:
        """Get importer for format."""
        importers = {
            DataFormat.JSON: JSONImporter,
            DataFormat.JSONL: JSONLImporter,
            DataFormat.CSV: CSVImporter,
            DataFormat.STIX: STIXImporter,
        }
        importer_class = importers.get(format)
        if not importer_class:
            raise ValueError(f"Unsupported import format: {format}")
        return importer_class(transformer=self._transformer)

    def _get_exporter(self, format: DataFormat) -> DataExporter:
        """Get exporter for format."""
        exporters = {
            DataFormat.JSON: JSONExporter,
            DataFormat.JSONL: JSONLExporter,
            DataFormat.CSV: CSVExporter,
            DataFormat.STIX: STIXExporter,
        }
        exporter_class = exporters.get(format)
        if not exporter_class:
            raise ValueError(f"Unsupported export format: {format}")
        return exporter_class(transformer=self._transformer)


# Convenience functions
def import_json(path: str | Path, **kwargs) -> tuple[list[dict], ImportResult]:
    """Import JSON file."""
    records = []
    importer = JSONImporter(on_record=lambda r: records.append(r), **kwargs)
    result = importer.import_file(path)
    return records, result


def import_jsonl(path: str | Path, **kwargs) -> tuple[list[dict], ImportResult]:
    """Import JSON Lines file."""
    records = []
    importer = JSONLImporter(on_record=lambda r: records.append(r), **kwargs)
    result = importer.import_file(path)
    return records, result


def import_csv(path: str | Path, **kwargs) -> tuple[list[dict], ImportResult]:
    """Import CSV file."""
    records = []
    importer = CSVImporter(on_record=lambda r: records.append(r), **kwargs)
    result = importer.import_file(path)
    return records, result


def import_stix(path: str | Path, **kwargs) -> tuple[list[dict], ImportResult]:
    """Import STIX file."""
    records = []
    importer = STIXImporter(on_record=lambda r: records.append(r), **kwargs)
    result = importer.import_file(path)
    return records, result


def export_json(records: list[dict], path: str | Path, **kwargs) -> ExportResult:
    """Export to JSON file."""
    exporter = JSONExporter(**kwargs)
    return exporter.export_file(records, path)


def export_jsonl(records: list[dict], path: str | Path, **kwargs) -> ExportResult:
    """Export to JSON Lines file."""
    exporter = JSONLExporter(**kwargs)
    return exporter.export_file(records, path)


def export_csv(records: list[dict], path: str | Path, **kwargs) -> ExportResult:
    """Export to CSV file."""
    exporter = CSVExporter(**kwargs)
    return exporter.export_file(records, path)


def export_stix(records: list[dict], path: str | Path, **kwargs) -> ExportResult:
    """Export to STIX file."""
    exporter = STIXExporter(**kwargs)
    return exporter.export_file(records, path)
