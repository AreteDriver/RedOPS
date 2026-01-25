"""Tests for documentation generator module."""

import json
import tempfile
from pathlib import Path

import pytest

from redops.core.docs_generator import (
    ClassDoc,
    CodeAnalyzer,
    DocstringParser,
    DocumentationGenerator,
    FunctionDoc,
    HTMLFormatter,
    JSONFormatter,
    MarkdownFormatter,
    ModuleDoc,
    OutputFormat,
    PackageDoc,
    Parameter,
    RSTFormatter,
    generate_docs,
)


class TestParameter:
    """Tests for Parameter dataclass."""

    def test_basic_creation(self):
        """Test basic parameter creation."""
        param = Parameter(name="arg1", type_hint="str", description="An argument")
        assert param.name == "arg1"
        assert param.type_hint == "str"
        assert param.description == "An argument"

    def test_to_dict(self):
        """Test conversion to dictionary."""
        param = Parameter(name="x", type_hint="int", default="0", description="Value")
        d = param.to_dict()
        assert d["name"] == "x"
        assert d["type"] == "int"
        assert d["default"] == "0"
        assert d["description"] == "Value"


class TestFunctionDoc:
    """Tests for FunctionDoc dataclass."""

    def test_basic_creation(self):
        """Test basic function doc creation."""
        doc = FunctionDoc(
            name="my_func",
            signature="(x: int, y: int) -> int",
            summary="Add two numbers",
        )
        assert doc.name == "my_func"
        assert doc.summary == "Add two numbers"

    def test_to_dict(self):
        """Test conversion to dictionary."""
        doc = FunctionDoc(
            name="test",
            signature="()",
            summary="Test function",
            parameters=[Parameter(name="arg1")],
        )
        d = doc.to_dict()
        assert d["name"] == "test"
        assert d["summary"] == "Test function"
        assert len(d["parameters"]) == 1

    def test_async_function(self):
        """Test async function doc."""
        doc = FunctionDoc(name="async_func", is_async=True)
        assert doc.is_async is True

    def test_decorators(self):
        """Test function with decorators."""
        doc = FunctionDoc(
            name="decorated",
            decorators=["staticmethod", "cache"],
        )
        assert "staticmethod" in doc.decorators


class TestClassDoc:
    """Tests for ClassDoc dataclass."""

    def test_basic_creation(self):
        """Test basic class doc creation."""
        doc = ClassDoc(
            name="MyClass",
            summary="A test class",
            bases=["BaseClass"],
        )
        assert doc.name == "MyClass"
        assert "BaseClass" in doc.bases

    def test_to_dict(self):
        """Test conversion to dictionary."""
        doc = ClassDoc(
            name="Test",
            methods=[FunctionDoc(name="method1")],
            class_methods=[FunctionDoc(name="classmethod1", is_classmethod=True)],
        )
        d = doc.to_dict()
        assert d["name"] == "Test"
        assert len(d["methods"]) == 1
        assert len(d["class_methods"]) == 1


class TestModuleDoc:
    """Tests for ModuleDoc dataclass."""

    def test_basic_creation(self):
        """Test basic module doc creation."""
        doc = ModuleDoc(
            name="my_module",
            path="/path/to/module.py",
            summary="A test module",
        )
        assert doc.name == "my_module"
        assert doc.summary == "A test module"

    def test_to_dict(self):
        """Test conversion to dictionary."""
        doc = ModuleDoc(
            name="test",
            classes=[ClassDoc(name="TestClass")],
            functions=[FunctionDoc(name="test_func")],
        )
        d = doc.to_dict()
        assert d["name"] == "test"
        assert len(d["classes"]) == 1
        assert len(d["functions"]) == 1


class TestPackageDoc:
    """Tests for PackageDoc dataclass."""

    def test_basic_creation(self):
        """Test basic package doc creation."""
        doc = PackageDoc(
            name="my_package",
            summary="A test package",
        )
        assert doc.name == "my_package"

    def test_to_dict(self):
        """Test conversion to dictionary."""
        doc = PackageDoc(
            name="pkg",
            modules=[ModuleDoc(name="mod1")],
            subpackages=[PackageDoc(name="subpkg")],
        )
        d = doc.to_dict()
        assert d["name"] == "pkg"
        assert len(d["modules"]) == 1
        assert len(d["subpackages"]) == 1


class TestDocstringParser:
    """Tests for DocstringParser class."""

    def test_parse_empty(self):
        """Test parsing empty docstring."""
        result = DocstringParser.parse(None)
        assert result["summary"] == ""
        assert result["params"] == []

    def test_parse_summary_only(self):
        """Test parsing docstring with only summary."""
        docstring = "This is a summary."
        result = DocstringParser.parse(docstring)
        assert result["summary"] == "This is a summary."

    def test_parse_with_description(self):
        """Test parsing docstring with summary and description."""
        docstring = """Short summary.

        This is a longer description that provides
        more details about the function.
        """
        result = DocstringParser.parse(docstring)
        assert result["summary"] == "Short summary."
        assert "longer description" in result["description"]

    def test_parse_parameters(self):
        """Test parsing parameters section."""
        docstring = """Function summary.

        Args:
            x (int): First parameter
            y (str): Second parameter
        """
        result = DocstringParser.parse(docstring)
        assert len(result["params"]) == 2
        assert result["params"][0]["name"] == "x"
        assert result["params"][0]["type"] == "int"
        assert result["params"][1]["name"] == "y"

    def test_parse_returns(self):
        """Test parsing returns section."""
        docstring = """Function summary.

        Returns:
            The computed result as an integer.
        """
        result = DocstringParser.parse(docstring)
        assert "computed result" in result["returns"]

    def test_parse_raises(self):
        """Test parsing raises section."""
        docstring = """Function summary.

        Raises:
            ValueError: If value is invalid
            TypeError: If type is wrong
        """
        result = DocstringParser.parse(docstring)
        assert len(result["raises"]) == 2
        assert any("ValueError" in r for r in result["raises"])

    def test_parse_examples(self):
        """Test parsing examples section."""
        docstring = """Function summary.

        Examples:
            >>> func(1, 2)
            3
            >>> func(0, 0)
            0
        """
        result = DocstringParser.parse(docstring)
        assert len(result["examples"]) >= 1

    def test_parse_alternative_section_names(self):
        """Test parsing with alternative section names."""
        docstring = """Summary.

        Parameters:
            x: A value

        Return:
            Result
        """
        result = DocstringParser.parse(docstring)
        assert len(result["params"]) == 1
        assert result["returns"] != ""


class TestCodeAnalyzer:
    """Tests for CodeAnalyzer class."""

    def test_analyze_simple_module(self, tmp_path):
        """Test analyzing a simple module."""
        module_code = '''
"""Module docstring.

This is a test module.
"""

CONSTANT = 42


def simple_function(x: int) -> int:
    """Return x doubled."""
    return x * 2


class SimpleClass:
    """A simple class."""

    def method(self, value: str) -> str:
        """Process value."""
        return value.upper()
'''
        module_file = tmp_path / "test_module.py"
        module_file.write_text(module_code)

        analyzer = CodeAnalyzer()
        doc = analyzer.analyze_module(module_file)

        assert doc.name == "test_module"
        assert "module docstring" in doc.summary.lower() or "test module" in doc.description.lower()
        assert len(doc.functions) == 1
        assert doc.functions[0].name == "simple_function"
        assert len(doc.classes) == 1
        assert doc.classes[0].name == "SimpleClass"

    def test_analyze_function_signature(self, tmp_path):
        """Test analyzing function signatures."""
        module_code = '''
def func_with_args(a: int, b: str = "default", *args, **kwargs) -> bool:
    """Test function."""
    return True
'''
        module_file = tmp_path / "test_sig.py"
        module_file.write_text(module_code)

        analyzer = CodeAnalyzer()
        doc = analyzer.analyze_module(module_file)

        func = doc.functions[0]
        assert "a: int" in func.signature
        assert "default" in func.signature
        assert func.return_type == "bool"

    def test_analyze_async_function(self, tmp_path):
        """Test analyzing async function."""
        module_code = '''
async def async_func() -> None:
    """Async function."""
    pass
'''
        module_file = tmp_path / "test_async.py"
        module_file.write_text(module_code)

        analyzer = CodeAnalyzer()
        doc = analyzer.analyze_module(module_file)

        assert doc.functions[0].is_async is True

    def test_analyze_class_methods(self, tmp_path):
        """Test analyzing class with various method types."""
        module_code = '''
class MyClass:
    """Test class."""

    @classmethod
    def class_method(cls):
        """A class method."""
        pass

    @staticmethod
    def static_method():
        """A static method."""
        pass

    @property
    def my_property(self):
        """A property."""
        return self._value

    def instance_method(self):
        """An instance method."""
        pass
'''
        module_file = tmp_path / "test_class.py"
        module_file.write_text(module_code)

        analyzer = CodeAnalyzer()
        doc = analyzer.analyze_module(module_file)

        cls = doc.classes[0]
        assert len(cls.class_methods) == 1
        assert len(cls.static_methods) == 1
        assert len(cls.properties) == 1
        assert len(cls.methods) >= 1

    def test_analyze_decorators(self, tmp_path):
        """Test analyzing decorated functions."""
        module_code = '''
def decorator(f):
    return f

@decorator
@another_decorator
def decorated_func():
    """Decorated function."""
    pass
'''
        module_file = tmp_path / "test_dec.py"
        module_file.write_text(module_code)

        analyzer = CodeAnalyzer()
        doc = analyzer.analyze_module(module_file)

        # Find the decorated function (not the decorator itself)
        func = next(f for f in doc.functions if f.name == "decorated_func")
        assert "decorator" in func.decorators

    def test_analyze_inheritance(self, tmp_path):
        """Test analyzing class inheritance."""
        module_code = '''
class Base:
    pass

class Child(Base):
    """Child class."""
    pass

class Multi(Base, object):
    """Multiple inheritance."""
    pass
'''
        module_file = tmp_path / "test_inherit.py"
        module_file.write_text(module_code)

        analyzer = CodeAnalyzer()
        doc = analyzer.analyze_module(module_file)

        child = next(c for c in doc.classes if c.name == "Child")
        assert "Base" in child.bases

        multi = next(c for c in doc.classes if c.name == "Multi")
        assert len(multi.bases) == 2


class TestMarkdownFormatter:
    """Tests for MarkdownFormatter class."""

    def test_format_function(self):
        """Test formatting function as markdown."""
        doc = FunctionDoc(
            name="test_func",
            signature="(x: int, y: int) -> int",
            summary="Add two numbers",
            parameters=[
                Parameter(name="x", type_hint="int", description="First number"),
                Parameter(name="y", type_hint="int", description="Second number"),
            ],
            returns="Sum of x and y",
            return_type="int",
        )

        formatter = MarkdownFormatter()
        result = formatter.format_function(doc)

        assert "## `test_func" in result
        assert "Add two numbers" in result
        assert "**x**" in result
        assert "**Parameters:**" in result
        assert "**Returns:**" in result

    def test_format_class(self):
        """Test formatting class as markdown."""
        doc = ClassDoc(
            name="TestClass",
            summary="A test class",
            bases=["BaseClass"],
            methods=[
                FunctionDoc(
                    name="method1",
                    signature="(self)",
                    summary="First method",
                )
            ],
        )

        formatter = MarkdownFormatter()
        result = formatter.format_class(doc)

        assert "## Class: `TestClass`" in result
        assert "**Inherits from:**" in result
        assert "BaseClass" in result
        assert "### Methods" in result

    def test_format_module(self):
        """Test formatting module as markdown."""
        doc = ModuleDoc(
            name="test_module",
            summary="A test module",
            classes=[ClassDoc(name="Class1", summary="First class")],
            functions=[FunctionDoc(name="func1", signature="()", summary="First function")],
        )

        formatter = MarkdownFormatter()
        result = formatter.format_module(doc)

        assert "# Module: `test_module`" in result
        assert "## Contents" in result
        assert "### Classes" in result
        assert "### Functions" in result

    def test_format_async_function(self):
        """Test formatting async function."""
        doc = FunctionDoc(
            name="async_func",
            signature="()",
            is_async=True,
        )

        formatter = MarkdownFormatter()
        result = formatter.format_function(doc)

        assert "async async_func" in result

    def test_format_with_examples(self):
        """Test formatting function with examples."""
        doc = FunctionDoc(
            name="example_func",
            signature="()",
            examples=[">>> example_func()\n42"],
        )

        formatter = MarkdownFormatter()
        result = formatter.format_function(doc)

        assert "**Examples:**" in result
        assert "```python" in result


class TestHTMLFormatter:
    """Tests for HTMLFormatter class."""

    def test_format_function(self):
        """Test formatting function as HTML."""
        doc = FunctionDoc(
            name="test_func",
            signature="(x: int) -> int",
            summary="A test function",
        )

        formatter = HTMLFormatter()
        result = formatter.format_function(doc)

        assert '<div class="doc-function"' in result
        assert "<code>test_func" in result
        assert "A test function" in result

    def test_format_class(self):
        """Test formatting class as HTML."""
        doc = ClassDoc(
            name="TestClass",
            summary="Test class",
            bases=["Base"],
        )

        formatter = HTMLFormatter()
        result = formatter.format_class(doc)

        assert '<div class="doc-class"' in result
        assert "TestClass" in result
        assert "<code>Base</code>" in result

    def test_format_module(self):
        """Test formatting module as HTML."""
        doc = ModuleDoc(
            name="test",
            summary="Test module",
        )

        formatter = HTMLFormatter()
        result = formatter.format_module(doc)

        assert '<div class="doc-module">' in result
        assert "<h1" in result

    def test_html_escaping(self):
        """Test HTML special character escaping."""
        doc = FunctionDoc(
            name="func",
            signature="(x: List[int])",
            summary="Test <script>alert('xss')</script>",
        )

        formatter = HTMLFormatter()
        result = formatter.format_function(doc)

        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_custom_css_prefix(self):
        """Test custom CSS class prefix."""
        doc = FunctionDoc(name="func", signature="()")
        formatter = HTMLFormatter(css_class_prefix="api")
        result = formatter.format_function(doc)

        assert 'class="api-function"' in result


class TestJSONFormatter:
    """Tests for JSONFormatter class."""

    def test_format_function(self):
        """Test formatting function as JSON."""
        doc = FunctionDoc(
            name="test_func",
            signature="()",
            summary="Test",
        )

        formatter = JSONFormatter()
        result = formatter.format_function(doc)

        parsed = json.loads(result)
        assert parsed["name"] == "test_func"
        assert parsed["summary"] == "Test"

    def test_format_module(self):
        """Test formatting module as JSON."""
        doc = ModuleDoc(
            name="test",
            classes=[ClassDoc(name="Class1")],
        )

        formatter = JSONFormatter()
        result = formatter.format_module(doc)

        parsed = json.loads(result)
        assert parsed["name"] == "test"
        assert len(parsed["classes"]) == 1

    def test_indentation(self):
        """Test JSON indentation."""
        doc = FunctionDoc(name="func", signature="()")

        formatter = JSONFormatter(indent=4)
        result = formatter.format_function(doc)

        assert "    " in result  # 4-space indent


class TestRSTFormatter:
    """Tests for RSTFormatter class."""

    def test_format_function(self):
        """Test formatting function as RST."""
        doc = FunctionDoc(
            name="test_func",
            signature="(x: int) -> int",
            summary="Test function",
            parameters=[Parameter(name="x", type_hint="int", description="Input")],
            return_type="int",
        )

        formatter = RSTFormatter()
        result = formatter.format_function(doc)

        assert ".. py:function:: test_func" in result
        assert ":param x" in result
        assert ":rtype: int" in result

    def test_format_class(self):
        """Test formatting class as RST."""
        doc = ClassDoc(
            name="TestClass",
            summary="Test class",
            bases=["Base"],
        )

        formatter = RSTFormatter()
        result = formatter.format_class(doc)

        assert "Class: TestClass" in result
        assert "---" in result
        assert "Base" in result

    def test_format_module(self):
        """Test formatting module as RST."""
        doc = ModuleDoc(
            name="test_module",
            summary="Test module",
        )

        formatter = RSTFormatter()
        result = formatter.format_module(doc)

        assert "Module: test_module" in result
        assert "===" in result


class TestDocumentationGenerator:
    """Tests for DocumentationGenerator class."""

    def test_generate_module_docs(self, tmp_path):
        """Test generating module documentation."""
        module_code = '''
"""Test module.

This is a test.
"""

def test_func():
    """A function."""
    pass
'''
        module_file = tmp_path / "test.py"
        module_file.write_text(module_code)

        generator = DocumentationGenerator(output_format=OutputFormat.MARKDOWN)
        result = generator.generate_module_docs(module_file)

        assert "# Module: `test`" in result
        assert "test_func" in result

    def test_generate_with_different_formats(self, tmp_path):
        """Test generating docs in different formats."""
        module_code = '''
"""Module."""

def func():
    """Function."""
    pass
'''
        module_file = tmp_path / "test.py"
        module_file.write_text(module_code)

        for fmt in [OutputFormat.MARKDOWN, OutputFormat.HTML, OutputFormat.JSON]:
            generator = DocumentationGenerator(output_format=fmt)
            result = generator.generate_module_docs(module_file)
            assert len(result) > 0

    def test_generate_class_docs(self):
        """Test generating class documentation."""

        class SampleClass:
            """A sample class for testing."""

            def method(self, x: int) -> str:
                """Convert x to string."""
                return str(x)

        generator = DocumentationGenerator()
        result = generator.generate_class_docs(SampleClass)

        assert "SampleClass" in result
        assert "sample class" in result.lower()

    def test_generate_function_docs(self):
        """Test generating function documentation."""

        def sample_func(a: int, b: int = 0) -> int:
            """Add two numbers.

            Args:
                a: First number
                b: Second number

            Returns:
                Sum of a and b
            """
            return a + b

        generator = DocumentationGenerator()
        result = generator.generate_function_docs(sample_func)

        assert "sample_func" in result
        assert "Add two numbers" in result

    def test_generate_package_docs(self, tmp_path):
        """Test generating package documentation."""
        # Create a simple package structure
        pkg_dir = tmp_path / "mypackage"
        pkg_dir.mkdir()

        (pkg_dir / "__init__.py").write_text('"""Package init."""')
        (pkg_dir / "module1.py").write_text('"""Module 1."""\ndef func1(): pass')
        (pkg_dir / "module2.py").write_text('"""Module 2."""\ndef func2(): pass')

        generator = DocumentationGenerator()
        docs = generator.generate_package_docs(pkg_dir)

        assert len(docs) >= 2  # At least module1 and module2
        assert any("module1" in k.lower() for k in docs.keys())

    def test_generate_package_with_output_dir(self, tmp_path):
        """Test generating package docs to output directory."""
        pkg_dir = tmp_path / "pkg"
        pkg_dir.mkdir()
        (pkg_dir / "mod.py").write_text('"""Module."""')

        output_dir = tmp_path / "docs"

        generator = DocumentationGenerator()
        generator.generate_package_docs(pkg_dir, output_dir=output_dir)

        assert output_dir.exists()
        assert any(output_dir.iterdir())

    def test_exclude_private_modules(self, tmp_path):
        """Test excluding private modules."""
        pkg_dir = tmp_path / "pkg"
        pkg_dir.mkdir()
        (pkg_dir / "public.py").write_text('"""Public."""')
        (pkg_dir / "_private.py").write_text('"""Private."""')

        generator = DocumentationGenerator(include_private=False)
        docs = generator.generate_package_docs(pkg_dir)

        assert any("public" in k for k in docs.keys())
        assert not any("_private" in k for k in docs.keys())

    def test_include_private_modules(self, tmp_path):
        """Test including private modules."""
        pkg_dir = tmp_path / "pkg"
        pkg_dir.mkdir()
        (pkg_dir / "_private.py").write_text('"""Private."""')

        generator = DocumentationGenerator(include_private=True)
        docs = generator.generate_package_docs(pkg_dir)

        assert any("_private" in k for k in docs.keys())


class TestGenerateDocsFunction:
    """Tests for generate_docs helper function."""

    def test_generate_from_path(self, tmp_path):
        """Test generating docs from file path."""
        module_file = tmp_path / "test.py"
        module_file.write_text('"""Test."""\ndef func(): pass')

        result = generate_docs(module_file)

        assert "test" in result.lower()

    def test_generate_with_output_path(self, tmp_path):
        """Test generating docs with output path."""
        module_file = tmp_path / "test.py"
        module_file.write_text('"""Test."""')
        output_file = tmp_path / "test.md"

        generate_docs(module_file, output_path=output_file)

        assert output_file.exists()
        assert output_file.read_text() != ""

    def test_generate_different_formats(self, tmp_path):
        """Test generating docs in different formats."""
        module_file = tmp_path / "test.py"
        module_file.write_text('"""Test."""')

        md = generate_docs(module_file, output_format=OutputFormat.MARKDOWN)
        html = generate_docs(module_file, output_format=OutputFormat.HTML)
        json_out = generate_docs(module_file, output_format=OutputFormat.JSON)

        assert "#" in md
        assert "<" in html
        assert "{" in json_out


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_module(self, tmp_path):
        """Test analyzing empty module."""
        module_file = tmp_path / "empty.py"
        module_file.write_text("")

        analyzer = CodeAnalyzer()
        doc = analyzer.analyze_module(module_file)

        assert doc.name == "empty"
        assert len(doc.classes) == 0
        assert len(doc.functions) == 0

    def test_syntax_error_in_module(self, tmp_path):
        """Test handling syntax errors."""
        module_file = tmp_path / "bad.py"
        module_file.write_text("def broken(:")

        analyzer = CodeAnalyzer()
        with pytest.raises(SyntaxError):
            analyzer.analyze_module(module_file)

    def test_complex_type_hints(self, tmp_path):
        """Test handling complex type hints."""
        module_code = '''
from typing import List, Dict, Optional, Union

def complex_func(
    items: List[Dict[str, int]],
    maybe: Optional[str] = None,
) -> Union[int, str]:
    """Complex types."""
    pass
'''
        module_file = tmp_path / "complex.py"
        module_file.write_text(module_code)

        analyzer = CodeAnalyzer()
        doc = analyzer.analyze_module(module_file)

        func = doc.functions[0]
        assert "List" in func.signature
        assert "Dict" in func.signature

    def test_multiline_docstring(self, tmp_path):
        """Test handling multiline docstrings."""
        module_code = '''
def func():
    """
    This is a very long docstring that spans
    multiple lines and contains various
    formatting elements.

    Args:
        none

    Returns:
        Nothing significant.
    """
    pass
'''
        module_file = tmp_path / "multiline.py"
        module_file.write_text(module_code)

        analyzer = CodeAnalyzer()
        doc = analyzer.analyze_module(module_file)

        assert doc.functions[0].summary != ""

    def test_nested_classes(self, tmp_path):
        """Test handling nested classes (outer only)."""
        module_code = '''
class Outer:
    """Outer class."""

    class Inner:
        """Inner class."""
        pass

    def method(self):
        pass
'''
        module_file = tmp_path / "nested.py"
        module_file.write_text(module_code)

        analyzer = CodeAnalyzer()
        doc = analyzer.analyze_module(module_file)

        # Should find outer class
        assert any(c.name == "Outer" for c in doc.classes)

    def test_special_characters_in_docstring(self, tmp_path):
        """Test handling special characters in docstrings."""
        module_code = '''
def func():
    """Handle <special> & "characters" properly."""
    pass
'''
        module_file = tmp_path / "special.py"
        module_file.write_text(module_code)

        generator = DocumentationGenerator(output_format=OutputFormat.HTML)
        result = generator.generate_module_docs(module_file)

        assert "&lt;" in result
        assert "&amp;" in result
