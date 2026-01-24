"""Tests for the EXIF metadata extraction module."""

import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from redops.core.context import Context
from redops.core.models import ExifData, RiskLevel
from redops.modules.metadata.exif import (
    extract_exif,
    extract_exif_from_file,
    scan_directory_for_images,
    parse_gps_info,
    dms_to_decimal,
    convert_exif_value,
    identify_sensitive_exif,
    analyze_exif_for_findings,
    strip_exif,
    get_exif_summary,
    PILLOW_AVAILABLE,
    IMAGE_EXTENSIONS,
    SENSITIVE_TAGS,
)


class TestDmsToDecimal:
    """Tests for DMS to decimal conversion."""

    def test_north_latitude(self):
        """Test converting north latitude."""
        dms = (40, 44, 55.0)
        result = dms_to_decimal(dms, "N")
        assert abs(result - 40.748611) < 0.0001

    def test_south_latitude(self):
        """Test converting south latitude."""
        dms = (33, 51, 54.0)
        result = dms_to_decimal(dms, "S")
        assert result < 0
        assert abs(result - (-33.865)) < 0.001

    def test_east_longitude(self):
        """Test converting east longitude."""
        dms = (151, 12, 36.0)
        result = dms_to_decimal(dms, "E")
        assert result > 0

    def test_west_longitude(self):
        """Test converting west longitude."""
        dms = (73, 59, 11.0)
        result = dms_to_decimal(dms, "W")
        assert result < 0

    def test_invalid_dms(self):
        """Test handling invalid DMS data."""
        result = dms_to_decimal(None, "N")
        assert result == 0.0

        result = dms_to_decimal((40,), "N")  # Too few elements
        assert result == 0.0


class TestConvertExifValue:
    """Tests for EXIF value conversion."""

    def test_convert_string(self):
        """Test converting string values."""
        assert convert_exif_value("test") == "test"

    def test_convert_int(self):
        """Test converting integer values."""
        assert convert_exif_value(42) == 42

    def test_convert_float(self):
        """Test converting float values."""
        assert convert_exif_value(3.14) == 3.14

    def test_convert_bytes(self):
        """Test converting bytes values."""
        result = convert_exif_value(b"test")
        assert result == "test"

    def test_convert_tuple(self):
        """Test converting tuple values."""
        result = convert_exif_value((1, 2, 3))
        assert result == [1, 2, 3]

    def test_convert_dict(self):
        """Test converting dict values."""
        result = convert_exif_value({1: "a", 2: "b"})
        assert result == {"1": "a", "2": "b"}

    def test_convert_ratio(self):
        """Test converting ratio values."""
        mock_ratio = MagicMock()
        mock_ratio.numerator = 3
        mock_ratio.denominator = 4
        result = convert_exif_value(mock_ratio)
        assert result == 0.75

    def test_convert_ratio_zero_denominator(self):
        """Test handling zero denominator in ratio."""
        mock_ratio = MagicMock()
        mock_ratio.numerator = 3
        mock_ratio.denominator = 0
        result = convert_exif_value(mock_ratio)
        assert result == 0.0


class TestParseGpsInfo:
    """Tests for GPS info parsing."""

    def test_parse_valid_gps(self):
        """Test parsing valid GPS data."""
        gps_info = {
            1: "N",  # Latitude ref
            2: (40, 44, 55.0),  # Latitude
            3: "W",  # Longitude ref
            4: (73, 59, 11.0),  # Longitude
        }
        result = parse_gps_info(gps_info)

        assert result is not None
        assert "latitude" in result
        assert "longitude" in result
        assert result["latitude"] > 0  # North
        assert result["longitude"] < 0  # West
        assert "google_maps_url" in result

    def test_parse_gps_with_altitude(self):
        """Test parsing GPS with altitude."""
        gps_info = {
            1: "N",
            2: (40, 44, 55.0),
            3: "W",
            4: (73, 59, 11.0),
            5: 0,  # Altitude ref (0 = above sea level)
            6: 100.5,  # Altitude
        }
        result = parse_gps_info(gps_info)

        assert result is not None
        assert "altitude" in result
        assert result["altitude"] == 100.5

    def test_parse_incomplete_gps(self):
        """Test parsing incomplete GPS data."""
        gps_info = {1: "N"}  # Missing coordinates
        result = parse_gps_info(gps_info)
        assert result is None

    def test_parse_empty_gps(self):
        """Test parsing empty GPS data."""
        result = parse_gps_info({})
        assert result is None


class TestIdentifySensitiveExif:
    """Tests for sensitive EXIF identification."""

    def test_identify_gps(self):
        """Test identifying GPS coordinates."""
        metadata = {
            "gps_coordinates": {"latitude": 40.7, "longitude": -73.9}
        }
        result = identify_sensitive_exif(metadata)
        assert any("GPS" in r for r in result)

    def test_identify_camera_info(self):
        """Test identifying camera information."""
        metadata = {
            "Make": "Canon",
            "Model": "EOS 5D",
        }
        result = identify_sensitive_exif(metadata)
        assert any("Make" in r for r in result)
        assert any("Model" in r for r in result)

    def test_identify_serial_number(self):
        """Test identifying serial numbers."""
        metadata = {"BodySerialNumber": "ABC123456"}
        result = identify_sensitive_exif(metadata)
        assert any("BodySerialNumber" in r for r in result)

    def test_no_sensitive_data(self):
        """Test when no sensitive data is present."""
        metadata = {"ImageWidth": 1920, "ImageHeight": 1080}
        result = identify_sensitive_exif(metadata)
        assert len(result) == 0


class TestAnalyzeExifForFindings:
    """Tests for EXIF findings analysis."""

    def test_gps_finding_high_severity(self):
        """Test that GPS creates HIGH severity finding."""
        exif_data = ExifData(
            filename="test.jpg",
            metadata={
                "gps_coordinates": {"latitude": 40.7, "longitude": -73.9}
            },
            sensitive_fields=["GPSInfo"],
            warnings=[],
        )

        findings = analyze_exif_for_findings(exif_data, "/path/test.jpg")

        assert len(findings) >= 1
        gps_finding = [f for f in findings if "GPS" in f.title][0]
        assert gps_finding.severity == RiskLevel.HIGH

    def test_serial_number_finding(self):
        """Test that serial numbers create findings."""
        exif_data = ExifData(
            filename="test.jpg",
            metadata={"BodySerialNumber": "ABC123"},
            sensitive_fields=["BodySerialNumber"],
            warnings=[],
        )

        findings = analyze_exif_for_findings(exif_data, "/path/test.jpg")

        assert len(findings) >= 1
        serial_finding = [f for f in findings if "Serial" in f.title][0]
        assert serial_finding.severity == RiskLevel.MEDIUM

    def test_personal_info_finding(self):
        """Test that personal info creates LOW severity finding."""
        exif_data = ExifData(
            filename="test.jpg",
            metadata={"Artist": "John Doe"},
            sensitive_fields=["Artist"],
            warnings=[],
        )

        findings = analyze_exif_for_findings(exif_data, "/path/test.jpg")

        assert len(findings) >= 1
        personal_finding = [f for f in findings if "Personal" in f.title][0]
        assert personal_finding.severity == RiskLevel.LOW

    def test_no_findings_for_clean_image(self):
        """Test no findings for image without sensitive data."""
        exif_data = ExifData(
            filename="test.jpg",
            metadata={"ImageWidth": 1920},
            sensitive_fields=[],
            warnings=[],
        )

        findings = analyze_exif_for_findings(exif_data, "/path/test.jpg")
        assert len(findings) == 0


class TestScanDirectoryForImages:
    """Tests for directory scanning."""

    def test_scan_empty_directory(self):
        """Test scanning empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            files = scan_directory_for_images(tmpdir)
            assert len(files) == 0

    def test_scan_directory_with_images(self):
        """Test scanning directory with image files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create fake image files
            Path(tmpdir, "test1.jpg").touch()
            Path(tmpdir, "test2.png").touch()
            Path(tmpdir, "test3.txt").touch()  # Non-image

            files = scan_directory_for_images(tmpdir)

            assert len(files) == 2
            assert all(f.suffix.lower() in IMAGE_EXTENSIONS for f in files)

    def test_scan_recursive(self):
        """Test recursive directory scanning."""
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = Path(tmpdir, "subdir")
            subdir.mkdir()
            Path(tmpdir, "test1.jpg").touch()
            Path(subdir, "test2.jpg").touch()

            files = scan_directory_for_images(tmpdir, recursive=True)
            assert len(files) == 2

    def test_scan_non_recursive(self):
        """Test non-recursive directory scanning."""
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = Path(tmpdir, "subdir")
            subdir.mkdir()
            Path(tmpdir, "test1.jpg").touch()
            Path(subdir, "test2.jpg").touch()

            files = scan_directory_for_images(tmpdir, recursive=False)
            assert len(files) == 1


class TestExtractExifFromFile:
    """Tests for single file EXIF extraction."""

    def test_nonexistent_file(self):
        """Test extraction from nonexistent file."""
        result = extract_exif_from_file("/nonexistent/path.jpg")
        assert result is None

    def test_non_image_file(self):
        """Test extraction from non-image file."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"not an image")
            result = extract_exif_from_file(f.name)
            assert result is None

    @pytest.mark.skipif(not PILLOW_AVAILABLE, reason="Pillow not available")
    def test_extract_from_real_image(self):
        """Test extraction from a real image (no EXIF)."""
        # Create a simple test image
        from PIL import Image
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            img = Image.new("RGB", (100, 100), color="red")
            img.save(f.name)

            result = extract_exif_from_file(f.name)

            assert result is not None
            assert result.filename.endswith(".jpg")
            assert "format" in result.metadata
            assert "size" in result.metadata


class TestExtractExif:
    """Tests for main extract_exif function."""

    def test_no_file_or_directory(self):
        """Test extraction without file or directory."""
        ctx = Context()
        result = extract_exif(ctx)

        warnings = result.get_logs(level="WARNING")
        assert any("no file" in log["message"].lower() for log in warnings)

    def test_extract_with_directory(self):
        """Test extraction with directory parameter."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target=tmpdir)
            result = extract_exif(ctx)

            assert "exif_data" in result.data
            assert "exif_summary" in result.data

    @pytest.mark.skipif(not PILLOW_AVAILABLE, reason="Pillow not available")
    def test_extract_creates_summary(self):
        """Test that extraction creates summary."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test image
            from PIL import Image
            img_path = Path(tmpdir, "test.jpg")
            img = Image.new("RGB", (100, 100), color="blue")
            img.save(str(img_path))

            ctx = Context(target=tmpdir)
            result = extract_exif(ctx)

            assert "exif_summary" in result.data
            summary = result.data["exif_summary"]
            assert "total_files" in summary


class TestGetExifSummary:
    """Tests for EXIF summary generation."""

    def test_empty_results(self):
        """Test summary for empty results."""
        summary = get_exif_summary([])

        assert summary["total_files"] == 0
        assert summary["files_with_gps"] == 0
        assert summary["files_with_sensitive"] == 0

    def test_summary_with_results(self):
        """Test summary with actual results."""
        results = [
            ExifData(
                filename="test1.jpg",
                metadata={
                    "Make": "Canon",
                    "gps_coordinates": {"latitude": 40.7, "longitude": -73.9},
                },
                sensitive_fields=["Make", "GPSInfo"],
                warnings=[],
            ),
            ExifData(
                filename="test2.jpg",
                metadata={"Make": "Nikon"},
                sensitive_fields=["Make"],
                warnings=[],
            ),
        ]

        summary = get_exif_summary(results)

        assert summary["total_files"] == 2
        assert summary["files_with_gps"] == 1
        assert summary["files_with_sensitive"] == 2
        assert "Canon" in summary["camera_makes"]
        assert "Nikon" in summary["camera_makes"]


class TestStripExif:
    """Tests for EXIF stripping."""

    @pytest.mark.skipif(not PILLOW_AVAILABLE, reason="Pillow not available")
    def test_strip_exif_creates_clean_image(self):
        """Test that strip_exif creates image without EXIF."""
        from PIL import Image

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test image
            input_path = Path(tmpdir, "input.jpg")
            output_path = Path(tmpdir, "output.jpg")

            img = Image.new("RGB", (100, 100), color="green")
            img.save(str(input_path))

            result = strip_exif(str(input_path), str(output_path))

            assert result is True
            assert output_path.exists()

    def test_strip_nonexistent_file(self):
        """Test stripping nonexistent file."""
        result = strip_exif("/nonexistent/path.jpg")
        assert result is False


class TestImageExtensions:
    """Tests for image extension handling."""

    def test_common_extensions_supported(self):
        """Test that common image extensions are supported."""
        common = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff"]
        for ext in common:
            assert ext in IMAGE_EXTENSIONS


class TestSensitiveTags:
    """Tests for sensitive tag definitions."""

    def test_gps_tags_included(self):
        """Test that GPS tags are in sensitive list."""
        assert "GPSInfo" in SENSITIVE_TAGS
        assert "GPSLatitude" in SENSITIVE_TAGS
        assert "GPSLongitude" in SENSITIVE_TAGS

    def test_personal_tags_included(self):
        """Test that personal info tags are in sensitive list."""
        assert "Artist" in SENSITIVE_TAGS
        assert "Copyright" in SENSITIVE_TAGS

    def test_device_tags_included(self):
        """Test that device info tags are in sensitive list."""
        assert "Make" in SENSITIVE_TAGS
        assert "Model" in SENSITIVE_TAGS
        assert "BodySerialNumber" in SENSITIVE_TAGS
