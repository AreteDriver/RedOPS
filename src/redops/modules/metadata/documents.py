"""
Document metadata extraction module.

Extracts metadata from PDF, Office documents, and other file types.
"""

from typing import Optional, Dict, Any, List
from pathlib import Path
from redops.core.context import Context
from redops.core.models import DocumentMetadata


def extract_metadata(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Extract metadata from documents.
    
    Args:
        ctx: Pipeline context
        params: Optional parameters including 'file_path' or 'directory'
        
    Returns:
        Updated context
    """
    params = params or {}
    file_path = params.get('file_path')
    directory = params.get('directory')
    
    if not file_path and not directory:
        ctx.log("No file or directory specified for metadata extraction", level="WARNING")
        return ctx
    
    metadata_results = []
    
    if file_path:
        result = extract_from_file(file_path)
        if result:
            metadata_results.append(result)
    
    if directory:
        ctx.log(f"Scanning directory for documents: {directory}", level="INFO")
        # Placeholder: would scan directory for document files
    
    ctx.add("document_metadata", [r.model_dump() for r in metadata_results])
    ctx.log(f"Metadata extraction completed, found {len(metadata_results)} files", level="INFO")
    
    return ctx


def extract_from_file(file_path: str) -> Optional[DocumentMetadata]:
    """
    Extract metadata from a single document file.
    
    Args:
        file_path: Path to the document
        
    Returns:
        DocumentMetadata object or None
    """
    path = Path(file_path)
    
    if not path.exists():
        return None
    
    file_type = path.suffix.lower()
    
    # Placeholder: Real implementation would use:
    # - PyPDF2 or pdfminer for PDFs
    # - python-docx for Word documents
    # - openpyxl for Excel files
    # - python-pptx for PowerPoint files
    
    doc_metadata = DocumentMetadata(
        filename=path.name,
        file_type=file_type,
        metadata={},
        warnings=[]
    )
    
    return doc_metadata


def extract_pdf_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract metadata from a PDF file.
    
    Args:
        file_path: Path to the PDF file
        
    Returns:
        Metadata dictionary
    """
    # Placeholder: Real implementation would use PyPDF2
    return {
        "author": None,
        "creator": None,
        "producer": None,
        "created": None,
        "modified": None
    }


def extract_office_metadata(file_path: str) -> Dict[str, Any]:
    """
    Extract metadata from Office documents (Word, Excel, PowerPoint).
    
    Args:
        file_path: Path to the Office document
        
    Returns:
        Metadata dictionary
    """
    # Placeholder: Real implementation would use python-docx, openpyxl, or python-pptx
    return {
        "author": None,
        "created": None,
        "modified": None,
        "last_modified_by": None,
        "revision": None
    }


def check_for_hidden_data(file_path: str) -> List[str]:
    """
    Check for hidden data in documents (comments, tracked changes, etc.).
    
    Args:
        file_path: Path to the document
        
    Returns:
        List of warnings about hidden data
    """
    warnings = []
    
    # Placeholder: Real implementation would check for:
    # - Comments
    # - Tracked changes
    # - Hidden sheets/slides
    # - Embedded objects
    # - Custom properties
    
    return warnings
