"""Tests for the Data Import/Export module."""

import gzip
import json
import os
import tempfile
from io import StringIO

import pytest

from redops.core.data_io import (
    BulkProcessor,
    CSVExporter,
    CSVImporter,
    DataFormat,
    DataTransformer,
    DataValidator,
    ExportResult,
    FormatConverter,
    ImportError,
    ImportResult,
    JSONExporter,
    JSONImporter,
    JSONLExporter,
    JSONLImporter,
    STIXExporter,
    STIXImporter,
    export_csv,
    export_json,
    export_jsonl,
    export_stix,
    import_csv,
    import_json,
    import_jsonl,
    import_stix,
)


class TestDataFormat:
    """Tests for DataFormat enum."""

    def test_all_formats_exist(self):
        """Test all formats are defined."""
        assert DataFormat.JSON.value == "json"
        assert DataFormat.JSONL.value == "jsonl"
        assert DataFormat.CSV.value == "csv"
        assert DataFormat.STIX.value == "stix"


class TestImportResult:
    """Tests for ImportResult."""

    def test_basic_result(self):
        """Test basic import result."""
        result = ImportResult(total_records=100, successful=95, failed=5)
        assert result.success_rate == 0.95

    def test_empty_result(self):
        """Test empty result."""
        result = ImportResult()
        assert result.success_rate == 0.0

    def test_to_dict(self):
        """Test serialization."""
        result = ImportResult(total_records=10, successful=8)
        d = result.to_dict()
        assert d["total_records"] == 10
        assert d["successful"] == 8


class TestExportResult:
    """Tests for ExportResult."""

    def test_basic_result(self):
        """Test basic export result."""
        result = ExportResult(total_records=100, exported=100)
        assert result.exported == 100

    def test_to_dict(self):
        """Test serialization."""
        result = ExportResult(total_records=10, exported=10, file_path="/tmp/test.json")
        d = result.to_dict()
        assert d["file_path"] == "/tmp/test.json"


class TestDataValidator:
    """Tests for DataValidator."""

    def test_required_fields(self):
        """Test required field validation."""
        validator = DataValidator().require("name", "email")

        assert validator.is_valid({"name": "John", "email": "john@example.com"})
        assert not validator.is_valid({"name": "John"})

    def test_field_types(self):
        """Test field type validation."""
        validator = DataValidator().expect_type("age", int)

        assert validator.is_valid({"age": 25})
        assert not validator.is_valid({"age": "25"})

    def test_custom_rules(self):
        """Test custom validation rules."""
        validator = DataValidator()
        validator.add_rule("age", lambda x: x >= 0, "Age must be non-negative")

        assert validator.is_valid({"age": 25})
        assert not validator.is_valid({"age": -5})

    def test_validate_returns_errors(self):
        """Test that validate returns error list."""
        validator = DataValidator().require("name")
        errors = validator.validate({})

        assert len(errors) == 1
        assert errors[0].field == "name"


class TestDataTransformer:
    """Tests for DataTransformer."""

    def test_simple_mapping(self):
        """Test simple field mapping."""
        transformer = DataTransformer()
        transformer.map_field("source_name", "target_name")

        result = transformer.transform({"source_name": "value"})
        assert result["target_name"] == "value"

    def test_nested_field(self):
        """Test nested field mapping."""
        transformer = DataTransformer()
        transformer.map_field("user.name", "name")

        result = transformer.transform({"user": {"name": "John"}})
        assert result["name"] == "John"

    def test_transform_function(self):
        """Test transform function."""
        transformer = DataTransformer()
        transformer.map_field("name", "upper_name", transform=str.upper)

        result = transformer.transform({"name": "john"})
        assert result["upper_name"] == "JOHN"

    def test_default_value(self):
        """Test default value."""
        transformer = DataTransformer()
        transformer.map_field("missing", "target", default="default_value")

        result = transformer.transform({})
        assert result["target"] == "default_value"

    def test_record_transform(self):
        """Test record-level transform."""

        def add_timestamp(record):
            record["processed"] = True
            return record

        transformer = DataTransformer()
        transformer.add_transform(add_timestamp)

        result = transformer.transform({"data": "value"})
        assert result["processed"] is True


class TestJSONImporter:
    """Tests for JSONImporter."""

    def test_import_array(self):
        """Test importing JSON array."""
        records = []
        importer = JSONImporter(on_record=lambda r: records.append(r))

        stream = StringIO('[{"name": "a"}, {"name": "b"}]')
        result = importer.import_stream(stream)

        assert result.successful == 2
        assert len(records) == 2

    def test_import_object(self):
        """Test importing single JSON object."""
        records = []
        importer = JSONImporter(on_record=lambda r: records.append(r))

        stream = StringIO('{"name": "single"}')
        result = importer.import_stream(stream)

        assert result.successful == 1

    def test_import_file(self):
        """Test importing from file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([{"id": 1}, {"id": 2}], f)
            path = f.name

        try:
            records = []
            importer = JSONImporter(on_record=lambda r: records.append(r))
            result = importer.import_file(path)

            assert result.successful == 2
        finally:
            os.unlink(path)

    def test_import_invalid_json(self):
        """Test importing invalid JSON."""
        importer = JSONImporter()
        stream = StringIO("not valid json")

        with pytest.raises(ImportError):
            importer.import_stream(stream)


class TestJSONLImporter:
    """Tests for JSONLImporter."""

    def test_import_jsonl(self):
        """Test importing JSON Lines."""
        records = []
        importer = JSONLImporter(on_record=lambda r: records.append(r))

        stream = StringIO('{"id": 1}\n{"id": 2}\n{"id": 3}')
        result = importer.import_stream(stream)

        assert result.successful == 3
        assert len(records) == 3

    def test_skip_empty_lines(self):
        """Test skipping empty lines."""
        records = []
        importer = JSONLImporter(on_record=lambda r: records.append(r))

        stream = StringIO('{"id": 1}\n\n{"id": 2}\n')
        result = importer.import_stream(stream)

        assert result.successful == 2

    def test_handle_invalid_line(self):
        """Test handling invalid JSON line."""
        importer = JSONLImporter()
        stream = StringIO('{"id": 1}\nnot json\n{"id": 2}')
        result = importer.import_stream(stream)

        assert result.successful == 2
        assert result.failed == 1

    def test_iter_records(self):
        """Test iterating over records."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            f.write('{"id": 1}\n{"id": 2}\n')
            path = f.name

        try:
            importer = JSONLImporter()
            records = list(importer.iter_records(path))
            assert len(records) == 2
        finally:
            os.unlink(path)

    def test_import_gzipped(self):
        """Test importing gzipped JSONL."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl.gz", delete=False) as f:
            path = f.name

        with gzip.open(path, "wt") as f:
            f.write('{"id": 1}\n{"id": 2}\n')

        try:
            records = []
            importer = JSONLImporter(on_record=lambda r: records.append(r))
            result = importer.import_file(path)

            assert result.successful == 2
        finally:
            os.unlink(path)


class TestCSVImporter:
    """Tests for CSVImporter."""

    def test_import_csv(self):
        """Test importing CSV."""
        records = []
        importer = CSVImporter(on_record=lambda r: records.append(r))

        stream = StringIO("name,age\nAlice,30\nBob,25")
        result = importer.import_stream(stream)

        assert result.successful == 2
        assert records[0]["name"] == "Alice"

    def test_custom_delimiter(self):
        """Test custom delimiter."""
        records = []
        importer = CSVImporter(delimiter=";", on_record=lambda r: records.append(r))

        stream = StringIO("name;age\nAlice;30")
        result = importer.import_stream(stream)

        assert result.successful == 1

    def test_without_header(self):
        """Test CSV without header."""
        records = []
        importer = CSVImporter(
            has_header=False,
            fieldnames=["name", "age"],
            on_record=lambda r: records.append(r),
        )

        stream = StringIO("Alice,30\nBob,25")
        result = importer.import_stream(stream)

        assert result.successful == 2
        assert records[0]["name"] == "Alice"


class TestSTIXImporter:
    """Tests for STIXImporter."""

    def test_import_bundle(self):
        """Test importing STIX bundle."""
        records = []
        importer = STIXImporter(on_record=lambda r: records.append(r))

        bundle = {
            "type": "bundle",
            "id": "bundle--12345",
            "objects": [
                {"type": "indicator", "id": "indicator--1", "spec_version": "2.1"},
                {"type": "malware", "id": "malware--1", "spec_version": "2.1"},
            ],
        }
        stream = StringIO(json.dumps(bundle))
        result = importer.import_stream(stream)

        assert result.successful == 2

    def test_import_array(self):
        """Test importing STIX array."""
        records = []
        importer = STIXImporter(on_record=lambda r: records.append(r))

        objects = [
            {"type": "indicator", "id": "indicator--1"},
        ]
        stream = StringIO(json.dumps(objects))
        result = importer.import_stream(stream)

        assert result.successful == 1

    def test_skip_non_stix(self):
        """Test skipping non-STIX objects."""
        records = []
        importer = STIXImporter(on_record=lambda r: records.append(r))

        bundle = {
            "type": "bundle",
            "objects": [
                {"type": "indicator", "id": "indicator--1"},
                {"type": "custom-type", "id": "custom--1"},
            ],
        }
        stream = StringIO(json.dumps(bundle))
        result = importer.import_stream(stream)

        assert result.successful == 1
        assert result.skipped == 1


class TestJSONExporter:
    """Tests for JSONExporter."""

    def test_export_json(self):
        """Test exporting JSON."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            records = [{"id": 1}, {"id": 2}]
            exporter = JSONExporter()
            result = exporter.export_file(records, path)

            assert result.exported == 2
            assert result.file_size_bytes > 0

            with open(path) as f:
                data = json.load(f)
            assert len(data) == 2
        finally:
            os.unlink(path)

    def test_export_pretty(self):
        """Test pretty JSON export."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            records = [{"id": 1}]
            exporter = JSONExporter(pretty=True)
            exporter.export_file(records, path)

            with open(path) as f:
                content = f.read()
            assert "\n" in content  # Pretty printing
        finally:
            os.unlink(path)

    def test_export_compressed(self):
        """Test compressed JSON export."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            records = [{"id": 1}]
            exporter = JSONExporter(compress=True)
            result = exporter.export_file(records, path)

            assert result.file_path.endswith(".gz")
        finally:
            if os.path.exists(path + ".gz"):
                os.unlink(path + ".gz")


class TestJSONLExporter:
    """Tests for JSONLExporter."""

    def test_export_jsonl(self):
        """Test exporting JSONL."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name

        try:
            records = [{"id": 1}, {"id": 2}]
            exporter = JSONLExporter()
            result = exporter.export_file(records, path)

            assert result.exported == 2

            with open(path) as f:
                lines = f.readlines()
            assert len(lines) == 2
        finally:
            os.unlink(path)


class TestCSVExporter:
    """Tests for CSVExporter."""

    def test_export_csv(self):
        """Test exporting CSV."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name

        try:
            records = [{"name": "Alice", "age": 30}, {"name": "Bob", "age": 25}]
            exporter = CSVExporter()
            result = exporter.export_file(records, path)

            assert result.exported == 2

            with open(path) as f:
                lines = f.readlines()
            assert len(lines) == 3  # Header + 2 rows
        finally:
            os.unlink(path)

    def test_custom_fieldnames(self):
        """Test custom field names."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name

        try:
            records = [{"name": "Alice", "age": 30, "extra": "ignored"}]
            exporter = CSVExporter(fieldnames=["name", "age"])
            exporter.export_file(records, path)

            with open(path) as f:
                header = f.readline()
            assert "extra" not in header
        finally:
            os.unlink(path)


class TestSTIXExporter:
    """Tests for STIXExporter."""

    def test_export_stix(self):
        """Test exporting STIX bundle."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            records = [
                {"type": "indicator", "pattern": "[domain-name:value = 'evil.com']"},
            ]
            exporter = STIXExporter()
            result = exporter.export_file(records, path)

            assert result.exported == 1

            with open(path) as f:
                bundle = json.load(f)
            assert bundle["type"] == "bundle"
            assert len(bundle["objects"]) == 1
        finally:
            os.unlink(path)

    def test_auto_generate_id(self):
        """Test auto-generating STIX ID."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            records = [{"type": "indicator"}]  # No ID
            exporter = STIXExporter()
            exporter.export_file(records, path)

            with open(path) as f:
                bundle = json.load(f)
            assert bundle["objects"][0]["id"].startswith("indicator--")
        finally:
            os.unlink(path)


class TestBulkProcessor:
    """Tests for BulkProcessor."""

    def test_batch_processing(self):
        """Test batch processing."""
        batches = []

        def on_batch(batch):
            batches.append(len(batch))

        processor = BulkProcessor(batch_size=3, on_batch=on_batch)
        records = [{"id": i} for i in range(10)]

        count = processor.process(iter(records))

        assert count == 10
        assert batches == [3, 3, 3, 1]

    def test_progress_callback(self):
        """Test progress callback."""
        progress = []

        def on_progress(current, total):
            progress.append((current, total))

        processor = BulkProcessor(batch_size=5, on_progress=on_progress)
        records = [{"id": i} for i in range(12)]

        processor.process(iter(records), total=12)

        assert len(progress) == 3  # Called after each batch


class TestFormatConverter:
    """Tests for FormatConverter."""

    def test_json_to_jsonl(self):
        """Test converting JSON to JSONL."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump([{"id": 1}, {"id": 2}], f)
            input_path = f.name

        output_path = input_path.replace(".json", ".jsonl")

        try:
            converter = FormatConverter()
            import_result, export_result = converter.convert(
                input_path,
                output_path,
                DataFormat.JSON,
                DataFormat.JSONL,
            )

            assert import_result.successful == 2
            assert export_result.exported == 2
        finally:
            os.unlink(input_path)
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_csv_to_json(self):
        """Test converting CSV to JSON."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            f.write("name,age\nAlice,30\nBob,25")
            input_path = f.name

        output_path = input_path.replace(".csv", ".json")

        try:
            converter = FormatConverter()
            import_result, export_result = converter.convert(
                input_path,
                output_path,
                DataFormat.CSV,
                DataFormat.JSON,
            )

            assert import_result.successful == 2
            assert export_result.exported == 2
        finally:
            os.unlink(input_path)
            if os.path.exists(output_path):
                os.unlink(output_path)


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_import_export_json(self):
        """Test import/export JSON convenience functions."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            # Export
            records = [{"id": 1}, {"id": 2}]
            result = export_json(records, path)
            assert result.exported == 2

            # Import
            imported, result = import_json(path)
            assert len(imported) == 2
        finally:
            os.unlink(path)

    def test_import_export_jsonl(self):
        """Test import/export JSONL convenience functions."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name

        try:
            records = [{"id": 1}, {"id": 2}]
            export_jsonl(records, path)

            imported, result = import_jsonl(path)
            assert len(imported) == 2
        finally:
            os.unlink(path)

    def test_import_export_csv(self):
        """Test import/export CSV convenience functions."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name

        try:
            records = [{"name": "Alice"}, {"name": "Bob"}]
            export_csv(records, path)

            imported, result = import_csv(path)
            assert len(imported) == 2
        finally:
            os.unlink(path)

    def test_import_export_stix(self):
        """Test import/export STIX convenience functions."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            records = [{"type": "indicator", "pattern": "test"}]
            export_stix(records, path)

            imported, result = import_stix(path)
            assert len(imported) == 1
        finally:
            os.unlink(path)


class TestValidationIntegration:
    """Tests for validation integration."""

    def test_import_with_validation(self):
        """Test importing with validation."""
        validator = DataValidator().require("id")
        records = []
        importer = JSONImporter(
            validator=validator,
            on_record=lambda r: records.append(r),
            skip_invalid=True,
        )

        stream = StringIO('[{"id": 1}, {"name": "no_id"}, {"id": 2}]')
        result = importer.import_stream(stream)

        assert result.successful == 2
        assert result.skipped == 1
        assert len(records) == 2


class TestTransformationIntegration:
    """Tests for transformation integration."""

    def test_import_with_transform(self):
        """Test importing with transformation."""
        transformer = DataTransformer()
        transformer.map_field("src_name", "name", transform=str.upper)

        records = []
        importer = JSONImporter(
            transformer=transformer,
            on_record=lambda r: records.append(r),
        )

        stream = StringIO('[{"src_name": "alice"}]')
        importer.import_stream(stream)

        assert records[0]["name"] == "ALICE"

    def test_export_with_transform(self):
        """Test exporting with transformation."""
        transformer = DataTransformer()
        transformer.map_field("name", "exported_name")

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name

        try:
            records = [{"name": "Alice"}]
            exporter = JSONExporter(transformer=transformer)
            exporter.export_file(records, path)

            with open(path) as f:
                data = json.load(f)
            assert data[0]["exported_name"] == "Alice"
        finally:
            os.unlink(path)
