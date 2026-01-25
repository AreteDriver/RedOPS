"""Tests for the EXIF metadata extraction module."""

import tempfile
import pytest
from pathlib import Path
from unittest.mock import MagicMock
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
        metadata = {"gps_coordinates": {"latitude": 40.7, "longitude": -73.9}}
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
            metadata={"gps_coordinates": {"latitude": 40.7, "longitude": -73.9}},
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


class TestPillowNotAvailable:
    """Tests for when Pillow is not available."""

    def test_extract_exif_without_pillow(self):
        """Test extract_exif when Pillow not available."""
        from unittest.mock import patch

        ctx = Context(target="/some/directory")

        with patch("redops.modules.metadata.exif.PILLOW_AVAILABLE", False):
            result = extract_exif(ctx)

        warnings = result.get_logs(level="WARNING")
        assert any("Pillow not available" in log["message"] for log in warnings)
        assert result.data.get("exif_data") == []

    def test_extract_exif_from_file_without_pillow(self):
        """Test extract_exif_from_file when Pillow not available."""
        from unittest.mock import patch

        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            f.write(b"fake image data")

            with patch("redops.modules.metadata.exif.PILLOW_AVAILABLE", False):
                result = extract_exif_from_file(f.name)

            assert result is None

    def test_strip_exif_without_pillow(self):
        """Test strip_exif when Pillow not available."""
        from unittest.mock import patch

        with patch("redops.modules.metadata.exif.PILLOW_AVAILABLE", False):
            result = strip_exif("/some/image.jpg")

        assert result is False


class TestExtractExifSingleFile:
    """Tests for single file extraction with findings."""

    @pytest.mark.skipif(not PILLOW_AVAILABLE, reason="Pillow not available")
    def test_extract_single_file_with_findings(self):
        """Test extracting EXIF from a single file generates findings."""
        from PIL import Image
        from unittest.mock import patch, MagicMock

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test image
            img_path = Path(tmpdir, "test.jpg")
            img = Image.new("RGB", (100, 100), color="red")
            img.save(str(img_path))

            # Mock extract_exif_from_file to return data with GPS
            mock_exif = ExifData(
                filename="test.jpg",
                metadata={
                    "gps_coordinates": {"latitude": 40.7, "longitude": -73.9},
                    "Make": "Canon",
                },
                sensitive_fields=["GPSInfo", "Make"],
                warnings=[],
            )

            ctx = Context()
            with patch("redops.modules.metadata.exif.extract_exif_from_file", return_value=mock_exif):
                result = extract_exif(ctx, {"file_path": str(img_path)})

            # Should have exif_data and findings
            assert "exif_data" in result.data
            # Findings should be added with finding_exif_N keys
            finding_keys = [k for k in result.data if k.startswith("finding_exif_")]
            assert len(finding_keys) > 0

    @pytest.mark.skipif(not PILLOW_AVAILABLE, reason="Pillow not available")
    def test_extract_logs_gps_warning(self):
        """Test that extraction logs GPS warning."""
        from PIL import Image
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmpdir:
            img_path = Path(tmpdir, "test.jpg")
            img = Image.new("RGB", (100, 100), color="red")
            img.save(str(img_path))

            mock_exif = ExifData(
                filename="test.jpg",
                metadata={"gps_coordinates": {"latitude": 40.7, "longitude": -73.9}},
                sensitive_fields=["GPSInfo"],
                warnings=[],
            )

            ctx = Context()
            with patch("redops.modules.metadata.exif.extract_exif_from_file", return_value=mock_exif):
                result = extract_exif(ctx, {"file_path": str(img_path)})

            warnings = result.get_logs(level="WARNING")
            assert any("GPS coordinates" in log["message"] for log in warnings)

    @pytest.mark.skipif(not PILLOW_AVAILABLE, reason="Pillow not available")
    def test_extract_logs_sensitive_data(self):
        """Test that extraction logs sensitive data info."""
        from PIL import Image
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmpdir:
            img_path = Path(tmpdir, "test.jpg")
            img = Image.new("RGB", (100, 100), color="red")
            img.save(str(img_path))

            mock_exif = ExifData(
                filename="test.jpg",
                metadata={"Make": "Canon", "Model": "EOS 5D"},
                sensitive_fields=["Make", "Model"],
                warnings=[],
            )

            ctx = Context()
            with patch("redops.modules.metadata.exif.extract_exif_from_file", return_value=mock_exif):
                result = extract_exif(ctx, {"file_path": str(img_path)})

            info_logs = result.get_logs(level="INFO")
            assert any("sensitive metadata" in log["message"] for log in info_logs)


class TestExtractExifFromFileEdgeCases:
    """Edge case tests for extract_exif_from_file."""

    @pytest.mark.skipif(not PILLOW_AVAILABLE, reason="Pillow not available")
    def test_extract_with_exif_and_gps(self):
        """Test extraction with EXIF data including GPS."""
        from PIL import Image
        from unittest.mock import patch, MagicMock

        # Create a mock image object with _getexif method
        mock_img = MagicMock()
        mock_img.format = "JPEG"
        mock_img.mode = "RGB"
        mock_img.width = 100
        mock_img.height = 100
        mock_img._getexif.return_value = {
            271: "Canon",  # Make
            272: "EOS 5D",  # Model
            34853: {  # GPSInfo
                1: "N",
                2: (40, 44, 55.0),
                3: "W",
                4: (73, 59, 11.0),
            },
        }
        mock_img.__enter__ = MagicMock(return_value=mock_img)
        mock_img.__exit__ = MagicMock(return_value=False)

        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            # Create actual image so file exists
            img = Image.new("RGB", (100, 100), color="red")
            img.save(f.name)

            with patch("redops.modules.metadata.exif.Image.open", return_value=mock_img):
                result = extract_exif_from_file(f.name)

            assert result is not None
            assert "gps_coordinates" in result.metadata
            assert "GPSInfo" in result.sensitive_fields

    @pytest.mark.skipif(not PILLOW_AVAILABLE, reason="Pillow not available")
    def test_extract_with_sensitive_tags(self):
        """Test extraction identifies sensitive tags."""
        from PIL import Image
        from unittest.mock import patch, MagicMock

        # Create a mock image object
        mock_img = MagicMock()
        mock_img.format = "JPEG"
        mock_img.mode = "RGB"
        mock_img.width = 100
        mock_img.height = 100
        mock_img._getexif.return_value = {
            271: "Canon",  # Make - sensitive
            315: "John Doe",  # Artist - sensitive
        }
        mock_img.__enter__ = MagicMock(return_value=mock_img)
        mock_img.__exit__ = MagicMock(return_value=False)

        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            img = Image.new("RGB", (100, 100), color="red")
            img.save(f.name)

            with patch("redops.modules.metadata.exif.Image.open", return_value=mock_img):
                result = extract_exif_from_file(f.name)

            assert result is not None
            assert "Make" in result.sensitive_fields or "Artist" in result.sensitive_fields

    @pytest.mark.skipif(not PILLOW_AVAILABLE, reason="Pillow not available")
    def test_extract_with_exception(self):
        """Test extraction handles exception gracefully."""
        from PIL import Image
        from unittest.mock import patch

        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            img = Image.new("RGB", (100, 100), color="red")
            img.save(f.name)

            # Mock Image.open to raise an exception after getting basic info
            original_open = Image.open

            def mock_open(path):
                img = original_open(path)
                # Make _getexif raise an exception
                img._getexif = lambda: (_ for _ in ()).throw(Exception("EXIF read error"))
                return img

            with patch.object(Image, "open", side_effect=mock_open):
                result = extract_exif_from_file(f.name)

            # Should return ExifData with warnings
            assert result is not None
            assert len(result.warnings) > 0
            assert any("Error" in w for w in result.warnings)


class TestParseGpsInfoEdgeCases:
    """Edge case tests for parse_gps_info."""

    def test_parse_gps_with_altitude_below_sea_level(self):
        """Test parsing GPS with altitude below sea level."""
        gps_info = {
            1: "N",
            2: (40, 44, 55.0),
            3: "W",
            4: (73, 59, 11.0),
            5: 1,  # Altitude ref (1 = below sea level)
            6: 50.0,  # Altitude
        }
        result = parse_gps_info(gps_info)

        assert result is not None
        assert "altitude" in result
        assert result["altitude"] == -50.0  # Negative because below sea level

    def test_parse_gps_exception_returns_none(self):
        """Test that parse exception returns None."""
        from unittest.mock import patch

        # Force dms_to_decimal to raise an exception
        with patch("redops.modules.metadata.exif.dms_to_decimal", side_effect=Exception("Conversion error")):
            gps_info = {
                1: "N",
                2: (40, 44, 55.0),
                3: "W",
                4: (73, 59, 11.0),
            }
            result = parse_gps_info(gps_info)
            assert result is None


class TestConvertExifValueEdgeCases:
    """Edge case tests for convert_exif_value."""

    def test_convert_bytes_with_decode_error(self):
        """Test converting bytes that fail to decode."""
        # Invalid UTF-8 bytes
        invalid_bytes = b"\xff\xfe\x00\x01"
        result = convert_exif_value(invalid_bytes)
        # Should still return a string (with replacement characters)
        assert isinstance(result, str)

    def test_convert_unknown_type_to_string(self):
        """Test converting unknown type falls back to str()."""
        # Create a custom object that isn't a basic type
        class CustomObject:
            def __str__(self):
                return "custom_object_string"

        obj = CustomObject()
        result = convert_exif_value(obj)
        assert result == "custom_object_string"

    def test_convert_none_value(self):
        """Test converting None returns None."""
        result = convert_exif_value(None)
        assert result is None

    def test_convert_bool_value(self):
        """Test converting boolean - bool has numerator/denominator so treated as ratio."""
        # In Python, bool is a subclass of int and has numerator/denominator
        # True.numerator = 1, True.denominator = 1
        # So convert_exif_value treats it as a ratio and returns 1.0
        assert convert_exif_value(True) == 1.0
        assert convert_exif_value(False) == 0.0


class TestStripExifEdgeCases:
    """Edge case tests for strip_exif."""

    @pytest.mark.skipif(not PILLOW_AVAILABLE, reason="Pillow not available")
    def test_strip_exif_exception(self):
        """Test strip_exif handles exception."""
        from unittest.mock import patch

        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            # Write invalid image data
            f.write(b"not a valid image")

            # This should fail and return False
            result = strip_exif(f.name)
            assert result is False


class TestGetExifSummaryEdgeCases:
    """Edge case tests for get_exif_summary."""

    def test_summary_counts_files_with_exif(self):
        """Test summary correctly counts files with EXIF."""
        results = [
            ExifData(
                filename="test1.jpg",
                metadata={
                    "format": "JPEG",
                    "mode": "RGB",
                    "size": {"width": 100, "height": 100},
                    "Make": "Canon",
                    "Model": "EOS",
                },  # More than 3 fields = has EXIF
                sensitive_fields=["Make"],
                warnings=[],
            ),
            ExifData(
                filename="test2.jpg",
                metadata={"format": "JPEG", "mode": "RGB"},  # Only basic info
                sensitive_fields=[],
                warnings=[],
            ),
        ]

        summary = get_exif_summary(results)

        assert summary["files_with_exif"] == 1

    def test_summary_tracks_software(self):
        """Test summary tracks software used."""
        results = [
            ExifData(
                filename="test1.jpg",
                metadata={"Software": "Adobe Photoshop"},
                sensitive_fields=["Software"],
                warnings=[],
            ),
            ExifData(
                filename="test2.jpg",
                metadata={"Software": "Adobe Photoshop"},
                sensitive_fields=["Software"],
                warnings=[],
            ),
            ExifData(
                filename="test3.jpg",
                metadata={"Software": "GIMP 2.10"},
                sensitive_fields=["Software"],
                warnings=[],
            ),
        ]

        summary = get_exif_summary(results)

        assert "Adobe Photoshop" in summary["software_used"]
        assert summary["software_used"]["Adobe Photoshop"] == 2
        assert "GIMP 2.10" in summary["software_used"]
        assert summary["software_used"]["GIMP 2.10"] == 1


class TestExtractExifWithDatetimeParsing:
    """Tests for datetime parsing in EXIF extraction."""

    @pytest.mark.skipif(not PILLOW_AVAILABLE, reason="Pillow not available")
    def test_extract_with_datetime_tags(self):
        """Test extraction parses datetime tags."""
        from PIL import Image
        from unittest.mock import patch, MagicMock

        mock_img = MagicMock()
        mock_img.format = "JPEG"
        mock_img.mode = "RGB"
        mock_img.width = 100
        mock_img.height = 100
        mock_img._getexif.return_value = {
            306: "2024:01:15 10:30:00",  # DateTime
            36867: "2024:01:15 10:29:55",  # DateTimeOriginal
            36868: "2024:01:15 10:29:55",  # DateTimeDigitized
        }
        mock_img.__enter__ = MagicMock(return_value=mock_img)
        mock_img.__exit__ = MagicMock(return_value=False)

        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as f:
            img = Image.new("RGB", (100, 100), color="red")
            img.save(f.name)

            with patch("redops.modules.metadata.exif.Image.open", return_value=mock_img):
                result = extract_exif_from_file(f.name)

            assert result is not None
            # Datetime tags should be present
            assert "DateTime" in result.metadata or "DateTimeOriginal" in result.metadata


class TestExtractExifDirectoryWithWarnings:
    """Tests for directory extraction with warnings filtering."""

    @pytest.mark.skipif(not PILLOW_AVAILABLE, reason="Pillow not available")
    def test_exclude_files_with_warnings(self):
        """Test excluding files with warnings when include_warnings=False."""
        from PIL import Image
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test images
            img_path = Path(tmpdir, "test.jpg")
            img = Image.new("RGB", (100, 100), color="red")
            img.save(str(img_path))

            # Mock to return result with warnings
            mock_exif_with_warning = ExifData(
                filename="test.jpg",
                metadata={},
                sensitive_fields=[],
                warnings=["No EXIF data found"],
            )

            ctx = Context(target=tmpdir)
            with patch("redops.modules.metadata.exif.extract_exif_from_file", return_value=mock_exif_with_warning):
                result = extract_exif(ctx, {"include_warnings": False})

            # Should not include the file since it has warnings
            assert result.data["exif_summary"]["total_files"] == 0
