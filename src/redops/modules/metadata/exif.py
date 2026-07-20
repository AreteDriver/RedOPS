"""
EXIF metadata extraction module.

Extracts EXIF metadata from images and identifies potentially sensitive information
such as GPS coordinates, camera info, and timestamps.
"""

from typing import Any
from pathlib import Path
from redops.core.context import Context
from redops.core.models import ExifData, Finding, RiskLevel

# Try to import Pillow for EXIF extraction
try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS

    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

# Image extensions to scan
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".gif", ".bmp", ".webp"}

# Sensitive EXIF tags that may leak information
SENSITIVE_TAGS = {
    "GPSInfo": "GPS location data",
    "GPSLatitude": "GPS latitude",
    "GPSLongitude": "GPS longitude",
    "GPSAltitude": "GPS altitude",
    "GPSLatitudeRef": "GPS latitude reference",
    "GPSLongitudeRef": "GPS longitude reference",
    "Artist": "Artist/creator name",
    "Copyright": "Copyright information",
    "Make": "Camera manufacturer",
    "Model": "Camera model",
    "Software": "Software used",
    "HostComputer": "Computer name",
    "CameraOwnerName": "Camera owner name",
    "BodySerialNumber": "Camera serial number",
    "LensSerialNumber": "Lens serial number",
    "ImageUniqueID": "Unique image identifier",
    "OwnerName": "Owner name",
    "SerialNumber": "Device serial number",
    "UserComment": "User comments",
    "XPAuthor": "Windows author",
    "XPComment": "Windows comment",
}


def extract_exif(ctx: Context, params: dict[str, Any] | None = None) -> Context:
    """
    Extract EXIF metadata from image files.

    Scans files for EXIF data and identifies sensitive information
    like GPS coordinates, camera info, and personal data.

    Args:
        ctx: Pipeline context
        params: Optional parameters
            - file_path: Single file to analyze
            - directory: Directory to scan for images
            - recursive: Scan subdirectories (default: True)
            - include_warnings: Include files with extraction warnings (default: True)

    Returns:
        Updated context with exif_data and findings
    """
    params = params or {}
    file_path = params.get("file_path")
    directory = params.get("directory") or ctx.target
    recursive = params.get("recursive", True)
    include_warnings = params.get("include_warnings", True)

    if not file_path and not directory:
        ctx.log("No file or directory specified for EXIF extraction", level="WARNING")
        return ctx

    if not PILLOW_AVAILABLE:
        ctx.log(
            "Pillow not available - install with: pip install Pillow", level="WARNING"
        )
        ctx.add("exif_data", [])
        return ctx

    exif_results: list[ExifData] = []
    findings: list[Finding] = []

    # Process single file
    if file_path:
        ctx.log(f"Extracting EXIF from file: {file_path}", level="INFO")
        result = extract_exif_from_file(file_path)
        if result:
            exif_results.append(result)
            file_findings = analyze_exif_for_findings(result, file_path)
            findings.extend(file_findings)

    # Process directory
    if directory:
        path = Path(directory)
        if path.is_dir():
            ctx.log(f"Scanning directory for images: {directory}", level="INFO")
            files = scan_directory_for_images(directory, recursive=recursive)
            ctx.log(f"Found {len(files)} image files", level="DEBUG")

            for img_file in files:
                result = extract_exif_from_file(str(img_file))
                if result:
                    if include_warnings or not result.warnings:
                        exif_results.append(result)
                        file_findings = analyze_exif_for_findings(result, str(img_file))
                        findings.extend(file_findings)

    # Add to context
    ctx.add("exif_data", [r.model_dump() for r in exif_results])

    # Add findings
    for i, finding in enumerate(findings):
        ctx.add(f"finding_exif_{i}", finding.model_dump())

    # Summary statistics
    files_with_gps = sum(1 for r in exif_results if "gps_coordinates" in r.metadata)
    files_with_sensitive = sum(1 for r in exif_results if r.sensitive_fields)

    ctx.log(
        f"EXIF extraction completed: {len(exif_results)} files processed", level="INFO"
    )
    if files_with_gps > 0:
        ctx.log(
            f"WARNING: {files_with_gps} files contain GPS coordinates", level="WARNING"
        )
    if files_with_sensitive > 0:
        ctx.log(
            f"Found {files_with_sensitive} files with sensitive metadata", level="INFO"
        )

    # Add summary
    ctx.add(
        "exif_summary",
        {
            "total_files": len(exif_results),
            "files_with_gps": files_with_gps,
            "files_with_sensitive_data": files_with_sensitive,
            "total_findings": len(findings),
        },
    )

    return ctx


def scan_directory_for_images(directory: str, recursive: bool = True) -> list[Path]:
    """
    Scan a directory for image files.

    Args:
        directory: Directory path to scan
        recursive: Whether to scan subdirectories

    Returns:
        List of image file paths
    """
    path = Path(directory)
    image_files = []

    if recursive:
        pattern = "**/*"
    else:
        pattern = "*"

    for file_path in path.glob(pattern):
        if file_path.is_file() and file_path.suffix.lower() in IMAGE_EXTENSIONS:
            image_files.append(file_path)

    return sorted(image_files)


def extract_exif_from_file(file_path: str) -> ExifData | None:
    """
    Extract EXIF data from a single image file.

    Args:
        file_path: Path to the image file

    Returns:
        ExifData object or None if extraction fails
    """
    path = Path(file_path)

    if not path.exists():
        return None

    if path.suffix.lower() not in IMAGE_EXTENSIONS:
        return None

    if not PILLOW_AVAILABLE:
        return None

    metadata: dict[str, Any] = {}
    sensitive_fields: list[str] = []
    warnings: list[str] = []

    try:
        with Image.open(file_path) as img:
            # Get basic image info
            metadata["format"] = img.format
            metadata["mode"] = img.mode
            metadata["size"] = {"width": img.width, "height": img.height}

            # Extract EXIF data
            exif_data = img._getexif()

            if exif_data:
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))

                    # Handle GPS data specially
                    if tag_name == "GPSInfo":
                        gps_data = parse_gps_info(value)
                        if gps_data:
                            metadata["gps_raw"] = {
                                GPSTAGS.get(k, k): convert_exif_value(v)
                                for k, v in value.items()
                            }
                            metadata["gps_coordinates"] = gps_data
                            sensitive_fields.append("GPSInfo")
                    else:
                        # Convert value to serializable format
                        converted_value = convert_exif_value(value)
                        metadata[tag_name] = converted_value

                        # Check if this is a sensitive field
                        if tag_name in SENSITIVE_TAGS:
                            sensitive_fields.append(tag_name)

                # Extract datetime info
                datetime_tags = ["DateTime", "DateTimeOriginal", "DateTimeDigitized"]
                for dt_tag in datetime_tags:
                    if dt_tag in metadata:
                        metadata[f"{dt_tag}_parsed"] = metadata[dt_tag]

            else:
                warnings.append("No EXIF data found in image")

    except (OSError, RuntimeError, ValueError, TypeError, KeyError, IndexError, AttributeError) as e:
        warnings.append(f"Error extracting EXIF: {str(e)}")
        return ExifData(
            filename=path.name,
            metadata=metadata,
            sensitive_fields=sensitive_fields,
            warnings=warnings,
        )

    return ExifData(
        filename=path.name,
        metadata=metadata,
        sensitive_fields=sensitive_fields,
        warnings=warnings,
    )


def parse_gps_info(gps_info: dict[int, Any]) -> dict[str, Any] | None:
    """
    Parse GPS EXIF data into readable coordinates.

    Args:
        gps_info: Raw GPS EXIF data dictionary

    Returns:
        Dictionary with decimal coordinates or None
    """
    try:
        # GPS tag IDs
        GPS_LATITUDE = 2
        GPS_LATITUDE_REF = 1
        GPS_LONGITUDE = 4
        GPS_LONGITUDE_REF = 3
        GPS_ALTITUDE = 6
        GPS_ALTITUDE_REF = 5

        lat = gps_info.get(GPS_LATITUDE)
        lat_ref = gps_info.get(GPS_LATITUDE_REF)
        lon = gps_info.get(GPS_LONGITUDE)
        lon_ref = gps_info.get(GPS_LONGITUDE_REF)

        if not (lat and lon):
            return None

        # Convert to decimal degrees
        lat_decimal = dms_to_decimal(lat, lat_ref)
        lon_decimal = dms_to_decimal(lon, lon_ref)

        result = {
            "latitude": lat_decimal,
            "longitude": lon_decimal,
            "latitude_ref": lat_ref,
            "longitude_ref": lon_ref,
        }

        # Add altitude if present
        altitude = gps_info.get(GPS_ALTITUDE)
        if altitude:
            alt_ref = gps_info.get(GPS_ALTITUDE_REF, 0)
            alt_value = float(altitude)
            if alt_ref == 1:  # Below sea level
                alt_value = -alt_value
            result["altitude"] = alt_value

        # Create Google Maps link
        result["google_maps_url"] = (
            f"https://maps.google.com/?q={lat_decimal},{lon_decimal}"
        )

        return result

    except (OSError, RuntimeError, ValueError, TypeError, KeyError, IndexError, AttributeError):
        return None


def dms_to_decimal(dms: tuple, ref: str) -> float:
    """
    Convert degrees/minutes/seconds to decimal degrees.

    Args:
        dms: Tuple of (degrees, minutes, seconds)
        ref: Reference direction (N, S, E, W)

    Returns:
        Decimal degrees
    """
    try:
        degrees = float(dms[0])
        minutes = float(dms[1])
        seconds = float(dms[2])

        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)

        if ref in ["S", "W"]:
            decimal = -decimal

        return round(decimal, 6)
    except (TypeError, IndexError, ValueError):
        return 0.0


def convert_exif_value(value: Any) -> Any:
    """
    Convert EXIF value to JSON-serializable format.

    Args:
        value: Raw EXIF value

    Returns:
        Serializable value
    """
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError):
            return str(value)
    elif isinstance(value, tuple):
        return [convert_exif_value(v) for v in value]
    elif isinstance(value, dict):
        return {str(k): convert_exif_value(v) for k, v in value.items()}
    elif hasattr(value, "numerator") and hasattr(value, "denominator"):
        # Handle Ratio types
        if value.denominator != 0:
            return float(value.numerator) / float(value.denominator)
        return 0.0
    else:
        try:
            # Try to convert to basic types
            if isinstance(value, (int, float, str, bool, type(None))):
                return value
            return str(value)
        except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError):
            return str(value)


def identify_sensitive_exif(metadata: dict[str, Any]) -> list[str]:
    """
    Identify potentially sensitive EXIF fields.

    Args:
        metadata: EXIF metadata dictionary

    Returns:
        List of sensitive field names with descriptions
    """
    sensitive_found = []

    for tag, description in SENSITIVE_TAGS.items():
        if tag in metadata:
            value = metadata[tag]
            if value and value != "Unknown":
                sensitive_found.append(f"{tag}: {description}")

    # Special check for GPS coordinates
    if "gps_coordinates" in metadata:
        coords = metadata["gps_coordinates"]
        sensitive_found.append(
            f"GPS Location: {coords.get('latitude')}, {coords.get('longitude')}"
        )

    return sensitive_found


def analyze_exif_for_findings(exif_data: ExifData, file_path: str) -> list[Finding]:
    """
    Analyze EXIF data and create security findings.

    Args:
        exif_data: Extracted EXIF data
        file_path: Path to the analyzed file

    Returns:
        List of Finding objects
    """
    findings = []

    # Check for GPS coordinates (high risk)
    if "gps_coordinates" in exif_data.metadata:
        coords = exif_data.metadata["gps_coordinates"]
        finding = Finding(
            module="metadata.exif",
            title=f"GPS Coordinates Exposed in {exif_data.filename}",
            description=f"Image contains GPS coordinates ({coords.get('latitude')}, {coords.get('longitude')}). This may reveal sensitive location information.",
            severity=RiskLevel.HIGH,
            data={
                "file": file_path,
                "coordinates": coords,
                "recommendation": "Strip EXIF data before publishing images",
            },
        )
        findings.append(finding)

    # Check for camera serial numbers (medium risk)
    serial_tags = ["BodySerialNumber", "LensSerialNumber", "SerialNumber"]
    for tag in serial_tags:
        if tag in exif_data.metadata and exif_data.metadata[tag]:
            finding = Finding(
                module="metadata.exif",
                title=f"Device Serial Number Exposed in {exif_data.filename}",
                description=f"Image contains {tag} which could identify the device owner.",
                severity=RiskLevel.MEDIUM,
                data={
                    "file": file_path,
                    "tag": tag,
                    "value": str(exif_data.metadata[tag])[:20] + "...",
                    "recommendation": "Strip EXIF data to prevent device tracking",
                },
            )
            findings.append(finding)
            break  # Only one finding per file for serial numbers

    # Check for owner/author names (low risk)
    name_tags = ["Artist", "CameraOwnerName", "OwnerName", "XPAuthor", "Copyright"]
    for tag in name_tags:
        if tag in exif_data.metadata and exif_data.metadata[tag]:
            finding = Finding(
                module="metadata.exif",
                title=f"Personal Information in {exif_data.filename}",
                description=f"Image contains {tag} metadata that may reveal personal information.",
                severity=RiskLevel.LOW,
                data={
                    "file": file_path,
                    "tag": tag,
                    "value": str(exif_data.metadata[tag])[:50],
                    "recommendation": "Review and strip personal metadata before sharing",
                },
            )
            findings.append(finding)
            break  # Only one finding per file for names

    return findings


def strip_exif(file_path: str, output_path: str | None = None) -> bool:
    """
    Strip EXIF data from an image file.

    Args:
        file_path: Path to the image file
        output_path: Optional output path (overwrites original if None)

    Returns:
        True if successful, False otherwise
    """
    if not PILLOW_AVAILABLE:
        return False

    try:
        path = Path(file_path)
        if not path.exists():
            return False

        with Image.open(file_path) as img:
            # Get image data without EXIF
            data = list(
                img.get_flattened_data()
                if hasattr(img, "get_flattened_data")
                else img.getdata()
            )

            # Create new image without EXIF
            img_no_exif = Image.new(img.mode, img.size)
            img_no_exif.putdata(data)

            # Save to output path or overwrite
            save_path = output_path or file_path
            img_no_exif.save(save_path)

            return True

    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError):
        return False


def get_exif_summary(exif_results: list[ExifData]) -> dict[str, Any]:
    """
    Generate a summary of EXIF extraction results.

    Args:
        exif_results: List of ExifData objects

    Returns:
        Summary dictionary
    """
    summary = {
        "total_files": len(exif_results),
        "files_with_exif": 0,
        "files_with_gps": 0,
        "files_with_sensitive": 0,
        "camera_makes": {},
        "software_used": {},
        "sensitive_tags_found": {},
    }

    for result in exif_results:
        if result.metadata and len(result.metadata) > 3:  # More than just basic info
            summary["files_with_exif"] += 1

        if "gps_coordinates" in result.metadata:
            summary["files_with_gps"] += 1

        if result.sensitive_fields:
            summary["files_with_sensitive"] += 1
            for field in result.sensitive_fields:
                summary["sensitive_tags_found"][field] = (
                    summary["sensitive_tags_found"].get(field, 0) + 1
                )

        # Track camera makes
        if "Make" in result.metadata:
            make = result.metadata["Make"]
            summary["camera_makes"][make] = summary["camera_makes"].get(make, 0) + 1

        # Track software
        if "Software" in result.metadata:
            software = result.metadata["Software"]
            summary["software_used"][software] = (
                summary["software_used"].get(software, 0) + 1
            )

    return summary
