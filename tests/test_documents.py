"""Tests for the document metadata extraction module."""

import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from redops.core.context import Context
from redops.core.models import DocumentMetadata, RiskLevel
from redops.modules.metadata.documents import (
    extract_metadata,
    extract_from_file,
    extract_pdf_metadata,
    extract_docx_metadata,
    check_docx_for_hidden_data,
    scan_directory_for_documents,
    analyze_document_for_findings,
    count_by_type,
    get_document_summary,
    check_for_hidden_data,
    extract_office_metadata,
    PYPDF_AVAILABLE,
    DOCX_AVAILABLE,
    DOCUMENT_EXTENSIONS,
    ALL_DOCUMENT_EXTENSIONS,
    SENSITIVE_FIELDS,
)


class TestDocumentExtensions:
    """Tests for document extension handling."""

    def test_pdf_extension_supported(self):
        """Test that PDF extension is supported."""
        assert ".pdf" in DOCUMENT_EXTENSIONS["pdf"]

    def test_word_extensions_supported(self):
        """Test that Word extensions are supported."""
        assert ".docx" in DOCUMENT_EXTENSIONS["word"]
        assert ".doc" in DOCUMENT_EXTENSIONS["word"]

    def test_excel_extensions_supported(self):
        """Test that Excel extensions are supported."""
        assert ".xlsx" in DOCUMENT_EXTENSIONS["excel"]
        assert ".xls" in DOCUMENT_EXTENSIONS["excel"]

    def test_powerpoint_extensions_supported(self):
        """Test that PowerPoint extensions are supported."""
        assert ".pptx" in DOCUMENT_EXTENSIONS["powerpoint"]
        assert ".ppt" in DOCUMENT_EXTENSIONS["powerpoint"]

    def test_all_extensions_combined(self):
        """Test that ALL_DOCUMENT_EXTENSIONS contains all types."""
        for ext_set in DOCUMENT_EXTENSIONS.values():
            for ext in ext_set:
                assert ext in ALL_DOCUMENT_EXTENSIONS


class TestSensitiveFields:
    """Tests for sensitive field definitions."""

    def test_author_field_included(self):
        """Test that author field is in sensitive list."""
        assert "author" in SENSITIVE_FIELDS

    def test_company_field_included(self):
        """Test that company field is in sensitive list."""
        assert "company" in SENSITIVE_FIELDS

    def test_creator_field_included(self):
        """Test that creator field is in sensitive list."""
        assert "creator" in SENSITIVE_FIELDS

    def test_last_modified_by_included(self):
        """Test that last_modified_by field is in sensitive list."""
        assert "last_modified_by" in SENSITIVE_FIELDS


class TestScanDirectoryForDocuments:
    """Tests for directory scanning."""

    def test_scan_empty_directory(self):
        """Test scanning empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            files = scan_directory_for_documents(tmpdir)
            assert len(files) == 0

    def test_scan_directory_with_documents(self):
        """Test scanning directory with document files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create fake document files
            Path(tmpdir, "test1.pdf").touch()
            Path(tmpdir, "test2.docx").touch()
            Path(tmpdir, "test3.txt").touch()  # Non-document

            files = scan_directory_for_documents(tmpdir)

            assert len(files) == 2
            assert all(f.suffix.lower() in ALL_DOCUMENT_EXTENSIONS for f in files)

    def test_scan_recursive(self):
        """Test recursive directory scanning."""
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = Path(tmpdir, "subdir")
            subdir.mkdir()
            Path(tmpdir, "test1.pdf").touch()
            Path(subdir, "test2.docx").touch()

            files = scan_directory_for_documents(tmpdir, recursive=True)
            assert len(files) == 2

    def test_scan_non_recursive(self):
        """Test non-recursive directory scanning."""
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = Path(tmpdir, "subdir")
            subdir.mkdir()
            Path(tmpdir, "test1.pdf").touch()
            Path(subdir, "test2.docx").touch()

            files = scan_directory_for_documents(tmpdir, recursive=False)
            assert len(files) == 1

    def test_scan_mixed_case_extensions(self):
        """Test scanning handles mixed case extensions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir, "test1.PDF").touch()
            Path(tmpdir, "test2.Docx").touch()
            Path(tmpdir, "test3.XLSX").touch()

            files = scan_directory_for_documents(tmpdir)
            assert len(files) == 3


class TestExtractFromFile:
    """Tests for single file extraction routing."""

    def test_nonexistent_file(self):
        """Test extraction from nonexistent file."""
        result = extract_from_file("/nonexistent/path.pdf")
        assert result is None

    def test_non_document_file(self):
        """Test extraction from non-document file."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"not a document")
            result = extract_from_file(f.name)
            assert result is None

    def test_legacy_doc_warning(self):
        """Test that legacy .doc files get a warning."""
        with tempfile.NamedTemporaryFile(suffix=".doc", delete=False) as f:
            f.write(b"fake doc content")
            result = extract_from_file(f.name)

            assert result is not None
            assert result.file_type == ".doc"
            assert any("Legacy" in w for w in result.warnings)

    def test_unsupported_format_warning(self):
        """Test that unsupported formats get a warning."""
        with tempfile.NamedTemporaryFile(suffix=".xls", delete=False) as f:
            f.write(b"fake excel content")
            result = extract_from_file(f.name)

            assert result is not None
            assert any("not implemented" in w for w in result.warnings)


class TestExtractPdfMetadata:
    """Tests for PDF metadata extraction."""

    def test_nonexistent_pdf(self):
        """Test extraction from nonexistent PDF."""
        result = extract_pdf_metadata("/nonexistent/path.pdf")
        # Without the file, we still get a DocumentMetadata with warnings
        assert result is not None
        assert any("Error" in w for w in result.warnings)

    @pytest.mark.skipif(not PYPDF_AVAILABLE, reason="pypdf not available")
    def test_extract_simple_pdf(self):
        """Test extraction from a simple PDF."""
        # Create a minimal PDF file
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            # Minimal PDF structure
            pdf_content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
trailer
<< /Size 4 /Root 1 0 R >>
startxref
196
%%EOF"""
            f.write(pdf_content)
            f.flush()

            result = extract_pdf_metadata(f.name)

            assert result is not None
            assert result.file_type == ".pdf"
            assert "page_count" in result.metadata

    @pytest.mark.skipif(not PYPDF_AVAILABLE, reason="pypdf not available")
    def test_pdf_with_mocked_metadata(self):
        """Test PDF metadata extraction with mocked reader."""
        with patch("redops.modules.metadata.documents.PdfReader") as mock_reader:
            mock_instance = MagicMock()
            mock_reader.return_value = mock_instance

            # Mock metadata
            mock_meta = MagicMock()
            mock_meta.author = "John Doe"
            mock_meta.creator = "Test Creator"
            mock_meta.producer = "Test Producer"
            mock_meta.subject = "Test Subject"
            mock_meta.title = "Test Title"
            mock_meta.creation_date = "2024-01-01"
            mock_meta.modification_date = "2024-01-02"
            mock_meta.__iter__ = lambda x: iter(["/CustomField"])
            mock_meta.__getitem__ = lambda x, k: "CustomValue"
            mock_instance.metadata = mock_meta

            # Mock pages
            mock_instance.pages = [MagicMock()]
            mock_instance.is_encrypted = False
            mock_instance.attachments = {}

            # Create a temp file
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
                f.write(b"fake pdf")

                result = extract_pdf_metadata(f.name)

                assert result is not None
                assert result.author == "John Doe"
                assert result.metadata.get("creator") == "Test Creator"
                assert result.metadata.get("title") == "Test Title"

    def test_pdf_unavailable_warning(self):
        """Test warning when pypdf not available."""
        with patch("redops.modules.metadata.documents.PYPDF_AVAILABLE", False):
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
                f.write(b"fake pdf")
                result = extract_pdf_metadata(f.name)

                assert result is not None
                assert any("pypdf not available" in w for w in result.warnings)


class TestExtractDocxMetadata:
    """Tests for Word document metadata extraction."""

    def test_docx_unavailable_warning(self):
        """Test warning when python-docx not available."""
        with patch("redops.modules.metadata.documents.DOCX_AVAILABLE", False):
            with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as f:
                f.write(b"fake docx")
                result = extract_docx_metadata(f.name)

                assert result is not None
                assert any("python-docx not available" in w for w in result.warnings)

    @pytest.mark.skipif(not DOCX_AVAILABLE, reason="python-docx not available")
    def test_invalid_docx(self):
        """Test extraction from invalid docx file."""
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as f:
            f.write(b"not a valid docx")

            result = extract_docx_metadata(f.name)

            assert result is not None
            assert any("Invalid" in w or "Error" in w for w in result.warnings)

    @pytest.mark.skipif(not DOCX_AVAILABLE, reason="python-docx not available")
    def test_docx_with_mocked_metadata(self):
        """Test docx metadata extraction with mocked document."""
        with patch("redops.modules.metadata.documents.DocxDocument") as mock_doc:
            mock_instance = MagicMock()
            mock_doc.return_value = mock_instance

            # Mock core properties
            mock_props = MagicMock()
            mock_props.author = "Jane Smith"
            mock_props.last_modified_by = "John Editor"
            mock_props.title = "Test Document"
            mock_props.subject = "Testing"
            mock_props.keywords = "test, demo"
            mock_props.comments = "Test comments"
            mock_props.category = "Test Category"
            mock_props.revision = "5"
            mock_props.created = "2024-01-01"
            mock_props.modified = "2024-01-15"
            mock_instance.core_properties = mock_props

            # Mock document structure
            mock_instance.paragraphs = [MagicMock(), MagicMock()]
            mock_instance.tables = [MagicMock()]

            # Mock part for hidden data check
            mock_rel = MagicMock()
            mock_rel.reltype = "normal"
            mock_instance.part.rels.values.return_value = [mock_rel]

            with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as f:
                f.write(b"fake docx")

                result = extract_docx_metadata(f.name)

                assert result is not None
                assert result.author == "Jane Smith"
                assert result.metadata.get("last_modified_by") == "John Editor"
                assert result.metadata.get("title") == "Test Document"


class TestCheckDocxForHiddenData:
    """Tests for hidden data detection in Word documents."""

    def test_high_revision_count_warning(self):
        """Test warning for high revision count."""
        mock_doc = MagicMock()
        mock_doc.core_properties.revision = "15"
        mock_doc.part.rels.values.return_value = []

        warnings = check_docx_for_hidden_data(mock_doc)

        assert any("revision count" in w.lower() for w in warnings)

    def test_embedded_ole_warning(self):
        """Test warning for embedded OLE objects."""
        mock_doc = MagicMock()
        mock_doc.core_properties.revision = "2"

        mock_rel = MagicMock()
        mock_rel.reltype = "oleObject"
        mock_doc.part.rels.values.return_value = [mock_rel]

        warnings = check_docx_for_hidden_data(mock_doc)

        assert any("OLE" in w for w in warnings)

    def test_no_warnings_clean_document(self):
        """Test no warnings for clean document."""
        mock_doc = MagicMock()
        mock_doc.core_properties.revision = "2"
        mock_doc.part.rels.values.return_value = []

        warnings = check_docx_for_hidden_data(mock_doc)

        assert len(warnings) == 0


class TestAnalyzeDocumentForFindings:
    """Tests for document findings analysis."""

    def test_author_finding(self):
        """Test that author creates a finding."""
        doc_meta = DocumentMetadata(
            filename="test.pdf",
            file_type=".pdf",
            author="John Doe",
            metadata={},
            warnings=[],
        )

        findings = analyze_document_for_findings(doc_meta, "/path/test.pdf")

        assert len(findings) >= 1
        author_finding = [f for f in findings if "Author" in f.title][0]
        assert author_finding.severity == RiskLevel.MEDIUM

    def test_last_modified_by_finding(self):
        """Test that different last_modified_by creates a finding."""
        doc_meta = DocumentMetadata(
            filename="test.docx",
            file_type=".docx",
            author="John Doe",
            metadata={"last_modified_by": "Jane Smith"},
            warnings=[],
        )

        findings = analyze_document_for_findings(doc_meta, "/path/test.docx")

        editor_findings = [f for f in findings if "Editor" in f.title]
        assert len(editor_findings) == 1
        assert editor_findings[0].severity == RiskLevel.LOW

    def test_same_author_modifier_no_extra_finding(self):
        """Test no extra finding when author and modifier are same."""
        doc_meta = DocumentMetadata(
            filename="test.docx",
            file_type=".docx",
            author="John Doe",
            metadata={"last_modified_by": "John Doe"},
            warnings=[],
        )

        findings = analyze_document_for_findings(doc_meta, "/path/test.docx")

        editor_findings = [f for f in findings if "Editor" in f.title]
        assert len(editor_findings) == 0

    def test_attachments_finding(self):
        """Test that embedded attachments create a finding."""
        doc_meta = DocumentMetadata(
            filename="test.pdf",
            file_type=".pdf",
            metadata={"attachments": ["secret.txt", "data.xlsx"]},
            warnings=[],
        )

        findings = analyze_document_for_findings(doc_meta, "/path/test.pdf")

        embed_findings = [f for f in findings if "Embedded" in f.title]
        assert len(embed_findings) == 1
        assert embed_findings[0].severity == RiskLevel.MEDIUM

    def test_ole_warning_finding(self):
        """Test that OLE warning creates a finding."""
        doc_meta = DocumentMetadata(
            filename="test.docx",
            file_type=".docx",
            metadata={},
            warnings=["Document contains embedded OLE objects"],
        )

        findings = analyze_document_for_findings(doc_meta, "/path/test.docx")

        hidden_findings = [f for f in findings if "Hidden" in f.title]
        assert len(hidden_findings) == 1

    def test_encrypted_finding(self):
        """Test that encryption creates an INFO finding."""
        doc_meta = DocumentMetadata(
            filename="test.pdf",
            file_type=".pdf",
            metadata={"encrypted": True},
            warnings=[],
        )

        findings = analyze_document_for_findings(doc_meta, "/path/test.pdf")

        encrypt_findings = [f for f in findings if "Encrypted" in f.title]
        assert len(encrypt_findings) == 1
        assert encrypt_findings[0].severity == RiskLevel.INFO

    def test_no_findings_clean_document(self):
        """Test no findings for clean document."""
        doc_meta = DocumentMetadata(
            filename="test.pdf",
            file_type=".pdf",
            metadata={"page_count": 5},
            warnings=[],
        )

        findings = analyze_document_for_findings(doc_meta, "/path/test.pdf")

        assert len(findings) == 0


class TestCountByType:
    """Tests for document type counting."""

    def test_empty_results(self):
        """Test counting empty results."""
        counts = count_by_type([])
        assert counts == {}

    def test_single_type(self):
        """Test counting single file type."""
        results = [
            DocumentMetadata(filename="a.pdf", file_type=".pdf", metadata={}),
            DocumentMetadata(filename="b.pdf", file_type=".pdf", metadata={}),
        ]

        counts = count_by_type(results)

        assert counts[".pdf"] == 2

    def test_multiple_types(self):
        """Test counting multiple file types."""
        results = [
            DocumentMetadata(filename="a.pdf", file_type=".pdf", metadata={}),
            DocumentMetadata(filename="b.docx", file_type=".docx", metadata={}),
            DocumentMetadata(filename="c.pdf", file_type=".pdf", metadata={}),
        ]

        counts = count_by_type(results)

        assert counts[".pdf"] == 2
        assert counts[".docx"] == 1


class TestGetDocumentSummary:
    """Tests for document summary generation."""

    def test_empty_results(self):
        """Test summary for empty results."""
        summary = get_document_summary([])

        assert summary["total_files"] == 0
        assert summary["files_with_author"] == 0
        assert summary["files_with_warnings"] == 0

    def test_summary_with_results(self):
        """Test summary with actual results."""
        results = [
            DocumentMetadata(
                filename="a.pdf",
                file_type=".pdf",
                author="John Doe",
                metadata={"creator": "Adobe Acrobat"},
                warnings=[],
            ),
            DocumentMetadata(
                filename="b.docx",
                file_type=".docx",
                author="Jane Smith",
                metadata={},
                warnings=["Some warning"],
            ),
            DocumentMetadata(
                filename="c.pdf",
                file_type=".pdf",
                metadata={"producer": "LaTeX"},
                warnings=[],
            ),
        ]

        summary = get_document_summary(results)

        assert summary["total_files"] == 3
        assert summary["files_with_author"] == 2
        assert summary["files_with_warnings"] == 1
        assert "John Doe" in summary["authors_found"]
        assert "Jane Smith" in summary["authors_found"]
        assert "Adobe Acrobat" in summary["software_found"]
        assert summary["by_type"][".pdf"] == 2
        assert summary["by_type"][".docx"] == 1


class TestCheckForHiddenData:
    """Tests for the check_for_hidden_data function."""

    def test_non_docx_file(self):
        """Test hidden data check for non-docx file."""
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            f.write(b"fake pdf")
            warnings = check_for_hidden_data(f.name)
            assert warnings == []

    @pytest.mark.skipif(not DOCX_AVAILABLE, reason="python-docx not available")
    def test_invalid_docx(self):
        """Test hidden data check for invalid docx."""
        with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as f:
            f.write(b"not a valid docx")
            warnings = check_for_hidden_data(f.name)
            assert any("Could not check" in w for w in warnings)


class TestExtractOfficeMetadata:
    """Tests for the generic Office metadata extraction."""

    def test_docx_routing(self):
        """Test that docx files are routed correctly."""
        with patch("redops.modules.metadata.documents.extract_docx_metadata") as mock:
            mock.return_value = DocumentMetadata(
                filename="test.docx",
                file_type=".docx",
                metadata={"test": "value"},
            )

            with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as f:
                result = extract_office_metadata(f.name)
                assert "test" in result

    def test_unsupported_format(self):
        """Test unsupported format returns warning."""
        with tempfile.NamedTemporaryFile(suffix=".pptx", delete=False) as f:
            f.write(b"fake pptx")
            result = extract_office_metadata(f.name)
            assert "warning" in result


class TestExtractMetadata:
    """Tests for main extract_metadata function."""

    def test_no_file_or_directory(self):
        """Test extraction without file or directory."""
        ctx = Context()
        result = extract_metadata(ctx)

        warnings = result.get_logs(level="WARNING")
        assert any("no file" in log["message"].lower() for log in warnings)

    def test_extract_with_empty_directory(self):
        """Test extraction with empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ctx = Context(target=tmpdir)
            result = extract_metadata(ctx)

            assert "document_metadata" in result.data
            assert "document_summary" in result.data

    def test_extract_with_file(self):
        """Test extraction with single file parameter."""
        with tempfile.NamedTemporaryFile(suffix=".doc", delete=False) as f:
            f.write(b"fake doc")

            ctx = Context()
            result = extract_metadata(ctx, params={"file_path": f.name})

            assert "document_metadata" in result.data
            metadata_list = result.data["document_metadata"]
            assert len(metadata_list) == 1

    def test_extract_creates_summary(self):
        """Test that extraction creates summary."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            Path(tmpdir, "test.pdf").touch()
            Path(tmpdir, "test.docx").touch()

            ctx = Context(target=tmpdir)
            result = extract_metadata(ctx)

            assert "document_summary" in result.data
            summary = result.data["document_summary"]
            assert "total_files" in summary
            assert "by_type" in summary

    def test_extract_with_findings(self):
        """Test that findings are added to context."""
        with patch(
            "redops.modules.metadata.documents.extract_from_file"
        ) as mock_extract:
            mock_extract.return_value = DocumentMetadata(
                filename="test.pdf",
                file_type=".pdf",
                author="Sensitive Author",
                metadata={},
                warnings=[],
            )

            with tempfile.TemporaryDirectory() as tmpdir:
                Path(tmpdir, "test.pdf").touch()

                ctx = Context(target=tmpdir)
                result = extract_metadata(ctx)

                # Check for findings in context
                finding_keys = [
                    k for k in result.data.keys() if k.startswith("finding_doc_")
                ]
                assert len(finding_keys) >= 1


class TestIntegration:
    """Integration tests requiring actual files."""

    @pytest.mark.skipif(not PYPDF_AVAILABLE, reason="pypdf not available")
    def test_full_pdf_workflow(self):
        """Test complete PDF extraction workflow."""
        # Create a minimal valid PDF
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            pdf_content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
trailer
<< /Size 4 /Root 1 0 R >>
startxref
196
%%EOF"""
            f.write(pdf_content)
            f.flush()

            # Test extraction
            result = extract_from_file(f.name)

            assert result is not None
            assert result.file_type == ".pdf"
            assert "page_count" in result.metadata or len(result.warnings) > 0

    def test_directory_scan_with_mixed_files(self):
        """Test scanning directory with various file types."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create various files
            Path(tmpdir, "doc1.pdf").touch()
            Path(tmpdir, "doc2.docx").touch()
            Path(tmpdir, "image.jpg").touch()  # Should be ignored
            Path(tmpdir, "readme.txt").touch()  # Should be ignored

            subdir = Path(tmpdir, "subdir")
            subdir.mkdir()
            Path(subdir, "doc3.xlsx").touch()

            # Scan recursively
            files = scan_directory_for_documents(tmpdir, recursive=True)

            assert len(files) == 3
            extensions = {f.suffix.lower() for f in files}
            assert ".pdf" in extensions
            assert ".docx" in extensions
            assert ".xlsx" in extensions
            assert ".jpg" not in extensions
