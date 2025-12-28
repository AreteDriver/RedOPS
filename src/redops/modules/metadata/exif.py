"""
EXIF metadata extraction module.

Extracts EXIF metadata from images and identifies potentially sensitive information.
"""

from typing import Optional, Dict, Any, List
from pathlib import Path
from redops.core.context import Context
from redops.core.models import ExifData


def extract_exif(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Extract EXIF metadata from image files.

    Args:
        ctx: Pipeline context
        params: Optional parameters including 'file_path' or 'directory'

    Returns:
        Updated context
    """
    params = params or {}
    file_path = params.get("file_path")
    directory = params.get("directory")

    if not file_path and not directory:
        ctx.log("No file or directory specified for EXIF extraction", level="WARNING")
        return ctx

    exif_results = []

    if file_path:
        result = extract_exif_from_file(file_path)
        if result:
            exif_results.append(result)

    if directory:
        ctx.log(f"Scanning directory for images: {directory}", level="INFO")
        # Placeholder: would scan directory for image files

    ctx.add("exif_data", [r.model_dump() for r in exif_results])
    ctx.log(f"EXIF extraction completed, found {len(exif_results)} files", level="INFO")

    return ctx


def extract_exif_from_file(file_path: str) -> Optional[ExifData]:
    """
    Extract EXIF data from a single image file.

    Args:
        file_path: Path to the image file

    Returns:
        ExifData object or None
    """
    path = Path(file_path)

    if not path.exists():
        return None

    # Placeholder: Real implementation would use PIL/Pillow or exifread
    exif_data = ExifData(
        filename=path.name, metadata={}, sensitive_fields=[], warnings=[]
    )

    # In a real implementation:
    # - Use PIL.Image or exifread to extract EXIF data
    # - Check for GPS coordinates
    # - Check for camera make/model
    # - Check for timestamps
    # - Check for software/creator info

    return exif_data


def identify_sensitive_exif(metadata: Dict[str, Any]) -> List[str]:
    """
    Identify potentially sensitive EXIF fields.

    Args:
        metadata: EXIF metadata dictionary

    Returns:
        List of sensitive field names
    """
    sensitive_fields = []

    sensitive_tags = [
        "GPSInfo",
        "GPSLatitude",
        "GPSLongitude",
        "GPSAltitude",
        "Artist",
        "Copyright",
        "Make",
        "Model",
        "Software",
        "OwnerName",
        "SerialNumber",
    ]

    for tag in sensitive_tags:
        if tag in metadata:
            sensitive_fields.append(tag)

    return sensitive_fields


def strip_exif(file_path: str, output_path: Optional[str] = None) -> bool:
    """
    Strip EXIF data from an image file.

    Args:
        file_path: Path to the image file
        output_path: Optional output path (overwrites if None)

    Returns:
        True if successful, False otherwise
    """
    # Placeholder: Real implementation would use PIL/Pillow
    return False
