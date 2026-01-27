"""
Documentation Generator Module for RedOPS.

Auto-generates API documentation from docstrings, module summaries,
and code structure with multiple output formats.
"""

import ast
import inspect
import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type, Union


class OutputFormat(Enum):
    """Documentation output formats."""

    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    RST = "rst"


@dataclass
class Parameter:
    """Function/method parameter documentation."""

    name: str
    type_hint: str = ""
    default: Optional[str] = None
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "type": self.type_hint,
            "default": self.default,
            "description": self.description,
        }


@dataclass
class FunctionDoc:
    """Documentation for a function or method."""

    name: str
    signature: str = ""
    docstring: str = ""
    summary: str = ""
    description: str = ""
    parameters: List[Parameter] = field(default_factory=list)
    returns: str = ""
    return_type: str = ""
    raises: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    decorators: List[str] = field(default_factory=list)
    is_async: bool = False
    is_classmethod: bool = False
    is_staticmethod: bool = False
    is_property: bool = False
    line_number: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "signature": self.signature,
            "summary": self.summary,
            "description": self.description,
            "parameters": [p.to_dict() for p in self.parameters],
            "returns": self.returns,
            "return_type": self.return_type,
            "raises": self.raises,
            "examples": self.examples,
            "decorators": self.decorators,
            "is_async": self.is_async,
            "is_classmethod": self.is_classmethod,
            "is_staticmethod": self.is_staticmethod,
            "is_property": self.is_property,
            "line_number": self.line_number,
        }


@dataclass
class ClassDoc:
    """Documentation for a class."""

    name: str
    docstring: str = ""
    summary: str = ""
    description: str = ""
    bases: List[str] = field(default_factory=list)
    methods: List[FunctionDoc] = field(default_factory=list)
    class_methods: List[FunctionDoc] = field(default_factory=list)
    static_methods: List[FunctionDoc] = field(default_factory=list)
    properties: List[FunctionDoc] = field(default_factory=list)
    attributes: List[Parameter] = field(default_factory=list)
    decorators: List[str] = field(default_factory=list)
    line_number: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "summary": self.summary,
            "description": self.description,
            "bases": self.bases,
            "methods": [m.to_dict() for m in self.methods],
            "class_methods": [m.to_dict() for m in self.class_methods],
            "static_methods": [m.to_dict() for m in self.static_methods],
            "properties": [p.to_dict() for p in self.properties],
            "attributes": [a.to_dict() for a in self.attributes],
            "decorators": self.decorators,
            "line_number": self.line_number,
        }


@dataclass
class ModuleDoc:
    """Documentation for a module."""

    name: str
    path: str = ""
    docstring: str = ""
    summary: str = ""
    description: str = ""
    classes: List[ClassDoc] = field(default_factory=list)
    functions: List[FunctionDoc] = field(default_factory=list)
    constants: List[Parameter] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    submodules: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "path": self.path,
            "summary": self.summary,
            "description": self.description,
            "classes": [c.to_dict() for c in self.classes],
            "functions": [f.to_dict() for f in self.functions],
            "constants": [c.to_dict() for c in self.constants],
            "imports": self.imports,
            "submodules": self.submodules,
        }


@dataclass
class PackageDoc:
    """Documentation for a package."""

    name: str
    path: str = ""
    docstring: str = ""
    summary: str = ""
    description: str = ""
    modules: List[ModuleDoc] = field(default_factory=list)
    subpackages: List["PackageDoc"] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "path": self.path,
            "summary": self.summary,
            "description": self.description,
            "modules": [m.to_dict() for m in self.modules],
            "subpackages": [p.to_dict() for p in self.subpackages],
        }


class DocstringParser:
    """Parse docstrings in various formats."""

    @staticmethod
    def parse(docstring: Optional[str]) -> Dict[str, Any]:
        """Parse a docstring and extract structured information."""
        if not docstring:
            return {
                "summary": "",
                "description": "",
                "params": [],
                "returns": "",
                "raises": [],
                "examples": [],
            }

        docstring = inspect.cleandoc(docstring)
        lines = docstring.split("\n")

        # Extract summary (first non-empty line)
        summary = ""
        description_lines = []
        params = []
        returns = ""
        raises = []
        examples = []

        # State machine for parsing
        current_section = "description"
        current_param = None
        example_buffer = []

        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            # Check for section headers
            if stripped.lower() in ("args:", "arguments:", "parameters:", "params:"):
                current_section = "params"
                i += 1
                continue
            elif stripped.lower() in ("returns:", "return:"):
                current_section = "returns"
                i += 1
                continue
            elif stripped.lower() in ("raises:", "raise:", "exceptions:"):
                current_section = "raises"
                i += 1
                continue
            elif stripped.lower() in ("examples:", "example:"):
                current_section = "examples"
                i += 1
                continue
            elif stripped.lower() in ("note:", "notes:"):
                current_section = "notes"
                i += 1
                continue
            elif stripped.lower() in ("attributes:", "attrs:"):
                current_section = "attributes"
                i += 1
                continue

            # Process based on current section
            if current_section == "description":
                if not summary and stripped:
                    summary = stripped
                elif stripped:
                    description_lines.append(stripped)
                elif description_lines:
                    description_lines.append("")

            elif current_section == "params":
                # Parse parameter: name (type): description
                param_match = re.match(
                    r"^\s*(\w+)\s*(?:\(([^)]+)\))?\s*:\s*(.*)$", line
                )
                if param_match:
                    if current_param:
                        params.append(current_param)
                    current_param = {
                        "name": param_match.group(1),
                        "type": param_match.group(2) or "",
                        "description": param_match.group(3),
                    }
                elif current_param and stripped:
                    current_param["description"] += " " + stripped

            elif current_section == "returns":
                if stripped:
                    returns += (" " if returns else "") + stripped

            elif current_section == "raises":
                # Parse: ExceptionType: description
                raise_match = re.match(r"^\s*(\w+)\s*:\s*(.*)$", line)
                if raise_match:
                    raises.append(f"{raise_match.group(1)}: {raise_match.group(2)}")
                elif stripped:
                    if raises:
                        raises[-1] += " " + stripped
                    else:
                        raises.append(stripped)

            elif current_section == "examples":
                if stripped.startswith(">>>") or stripped.startswith("..."):
                    example_buffer.append(stripped)
                elif example_buffer and not stripped:
                    examples.append("\n".join(example_buffer))
                    example_buffer = []
                elif stripped:
                    example_buffer.append(stripped)

            i += 1

        # Finalize
        if current_param:
            params.append(current_param)
        if example_buffer:
            examples.append("\n".join(example_buffer))

        return {
            "summary": summary,
            "description": "\n".join(description_lines).strip(),
            "params": params,
            "returns": returns,
            "raises": raises,
            "examples": examples,
        }


class CodeAnalyzer:
    """Analyze Python code to extract documentation."""

    def __init__(self):
        self._parser = DocstringParser()

    def analyze_module(self, module_path: Path) -> ModuleDoc:
        """Analyze a Python module file."""
        source = module_path.read_text()
        tree = ast.parse(source)

        module_doc = ModuleDoc(
            name=module_path.stem,
            path=str(module_path),
        )

        # Get module docstring
        if (
            tree.body
            and isinstance(tree.body[0], ast.Expr)
            and isinstance(tree.body[0].value, ast.Constant)
        ):
            module_doc.docstring = tree.body[0].value.value
            parsed = self._parser.parse(module_doc.docstring)
            module_doc.summary = parsed["summary"]
            module_doc.description = parsed["description"]

        # Analyze top-level elements
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                module_doc.classes.append(self._analyze_class(node, source))
            elif isinstance(node, ast.FunctionDef) or isinstance(
                node, ast.AsyncFunctionDef
            ):
                module_doc.functions.append(self._analyze_function(node))
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        if target.id.isupper():
                            module_doc.constants.append(
                                Parameter(
                                    name=target.id,
                                    type_hint=self._get_type_comment(node),
                                )
                            )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    module_doc.imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    module_doc.imports.append(node.module)

        return module_doc

    def analyze_module_object(self, module: Any) -> ModuleDoc:
        """Analyze a loaded Python module object."""
        module_doc = ModuleDoc(
            name=module.__name__,
            path=getattr(module, "__file__", ""),
        )

        # Get module docstring
        if module.__doc__:
            module_doc.docstring = module.__doc__
            parsed = self._parser.parse(module_doc.docstring)
            module_doc.summary = parsed["summary"]
            module_doc.description = parsed["description"]

        # Analyze members
        for name, obj in inspect.getmembers(module):
            if name.startswith("_"):
                continue

            if inspect.isclass(obj) and obj.__module__ == module.__name__:
                module_doc.classes.append(self._analyze_class_object(obj))
            elif inspect.isfunction(obj) and obj.__module__ == module.__name__:
                module_doc.functions.append(self._analyze_function_object(obj))

        return module_doc

    def _analyze_class(self, node: ast.ClassDef, source: str) -> ClassDoc:
        """Analyze a class definition."""
        class_doc = ClassDoc(
            name=node.name,
            line_number=node.lineno,
        )

        # Get bases
        for base in node.bases:
            class_doc.bases.append(ast.unparse(base))

        # Get decorators
        for decorator in node.decorator_list:
            class_doc.decorators.append(ast.unparse(decorator))

        # Get docstring
        if (
            node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
        ):
            class_doc.docstring = node.body[0].value.value
            parsed = self._parser.parse(class_doc.docstring)
            class_doc.summary = parsed["summary"]
            class_doc.description = parsed["description"]

        # Analyze methods
        for item in node.body:
            if isinstance(item, ast.FunctionDef) or isinstance(
                item, ast.AsyncFunctionDef
            ):
                func_doc = self._analyze_function(item)

                if func_doc.is_classmethod:
                    class_doc.class_methods.append(func_doc)
                elif func_doc.is_staticmethod:
                    class_doc.static_methods.append(func_doc)
                elif func_doc.is_property:
                    class_doc.properties.append(func_doc)
                elif not func_doc.name.startswith("_") or func_doc.name == "__init__":
                    class_doc.methods.append(func_doc)

        return class_doc

    def _analyze_class_object(self, cls: Type) -> ClassDoc:
        """Analyze a class object."""
        class_doc = ClassDoc(
            name=cls.__name__,
        )

        # Get bases
        for base in cls.__bases__:
            if base is not object:
                class_doc.bases.append(base.__name__)

        # Get docstring
        if cls.__doc__:
            class_doc.docstring = cls.__doc__
            parsed = self._parser.parse(cls.__doc__)
            class_doc.summary = parsed["summary"]
            class_doc.description = parsed["description"]

        # Analyze methods
        for name, method in inspect.getmembers(cls):
            if name.startswith("_") and name != "__init__":
                continue

            if isinstance(inspect.getattr_static(cls, name), classmethod):
                class_doc.class_methods.append(
                    self._analyze_function_object(method, is_classmethod=True)
                )
            elif isinstance(inspect.getattr_static(cls, name), staticmethod):
                class_doc.static_methods.append(
                    self._analyze_function_object(method, is_staticmethod=True)
                )
            elif isinstance(inspect.getattr_static(cls, name), property):
                prop = inspect.getattr_static(cls, name)
                class_doc.properties.append(
                    FunctionDoc(
                        name=name,
                        docstring=prop.fget.__doc__ if prop.fget else "",
                        is_property=True,
                    )
                )
            elif inspect.isfunction(method) or inspect.ismethod(method):
                class_doc.methods.append(self._analyze_function_object(method))

        return class_doc

    def _analyze_function(
        self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]
    ) -> FunctionDoc:
        """Analyze a function definition."""
        func_doc = FunctionDoc(
            name=node.name,
            line_number=node.lineno,
            is_async=isinstance(node, ast.AsyncFunctionDef),
        )

        # Get decorators
        for decorator in node.decorator_list:
            dec_name = ast.unparse(decorator)
            func_doc.decorators.append(dec_name)
            if "classmethod" in dec_name:
                func_doc.is_classmethod = True
            elif "staticmethod" in dec_name:
                func_doc.is_staticmethod = True
            elif "property" in dec_name:
                func_doc.is_property = True

        # Build signature
        args = []
        for arg in node.args.args:
            arg_str = arg.arg
            if arg.annotation:
                arg_str += f": {ast.unparse(arg.annotation)}"
            args.append(arg_str)

        # Handle defaults
        defaults = node.args.defaults
        if defaults:
            offset = len(args) - len(defaults)
            for i, default in enumerate(defaults):
                args[offset + i] += f" = {ast.unparse(default)}"

        func_doc.signature = f"({', '.join(args)})"

        # Return type
        if node.returns:
            func_doc.return_type = ast.unparse(node.returns)
            func_doc.signature += f" -> {func_doc.return_type}"

        # Get docstring
        if (
            node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
        ):
            func_doc.docstring = node.body[0].value.value
            parsed = self._parser.parse(func_doc.docstring)
            func_doc.summary = parsed["summary"]
            func_doc.description = parsed["description"]
            func_doc.returns = parsed["returns"]
            func_doc.raises = parsed["raises"]
            func_doc.examples = parsed["examples"]

            for param in parsed["params"]:
                func_doc.parameters.append(
                    Parameter(
                        name=param["name"],
                        type_hint=param["type"],
                        description=param["description"],
                    )
                )

        return func_doc

    def _analyze_function_object(
        self,
        func: Callable,
        is_classmethod: bool = False,
        is_staticmethod: bool = False,
    ) -> FunctionDoc:
        """Analyze a function object."""
        func_doc = FunctionDoc(
            name=func.__name__,
            is_classmethod=is_classmethod,
            is_staticmethod=is_staticmethod,
        )

        # Get signature
        try:
            sig = inspect.signature(func)
            func_doc.signature = str(sig)
            if sig.return_annotation != inspect.Parameter.empty:
                func_doc.return_type = str(sig.return_annotation)

            # Get parameters
            for name, param in sig.parameters.items():
                if name == "self" or name == "cls":
                    continue
                p = Parameter(name=name)
                if param.annotation != inspect.Parameter.empty:
                    p.type_hint = str(param.annotation)
                if param.default != inspect.Parameter.empty:
                    p.default = repr(param.default)
                func_doc.parameters.append(p)
        except (ValueError, TypeError):
            pass

        # Get docstring
        if func.__doc__:
            func_doc.docstring = func.__doc__
            parsed = self._parser.parse(func.__doc__)
            func_doc.summary = parsed["summary"]
            func_doc.description = parsed["description"]
            func_doc.returns = parsed["returns"]
            func_doc.raises = parsed["raises"]
            func_doc.examples = parsed["examples"]

            # Merge param descriptions
            param_descs = {p["name"]: p["description"] for p in parsed["params"]}
            for param in func_doc.parameters:
                if param.name in param_descs:
                    param.description = param_descs[param.name]

        # Check if async
        func_doc.is_async = inspect.iscoroutinefunction(func)

        return func_doc

    def _get_type_comment(self, node: ast.AST) -> str:
        """Extract type comment if present."""
        if hasattr(node, "type_comment") and node.type_comment:
            return node.type_comment
        return ""


class DocFormatter(ABC):
    """Base class for documentation formatters."""

    @abstractmethod
    def format_module(self, doc: ModuleDoc) -> str:
        """Format module documentation."""
        pass

    @abstractmethod
    def format_class(self, doc: ClassDoc) -> str:
        """Format class documentation."""
        pass

    @abstractmethod
    def format_function(self, doc: FunctionDoc) -> str:
        """Format function documentation."""
        pass

    @abstractmethod
    def format_package(self, doc: PackageDoc) -> str:
        """Format package documentation."""
        pass


class MarkdownFormatter(DocFormatter):
    """Format documentation as Markdown."""

    def __init__(self, include_source_links: bool = False):
        self._include_source_links = include_source_links

    def format_module(self, doc: ModuleDoc) -> str:
        """Format module documentation as Markdown."""
        lines = []

        # Title
        lines.append(f"# Module: `{doc.name}`")
        lines.append("")

        # Summary
        if doc.summary:
            lines.append(doc.summary)
            lines.append("")

        # Description
        if doc.description:
            lines.append(doc.description)
            lines.append("")

        # Table of contents
        if doc.classes or doc.functions:
            lines.append("## Contents")
            lines.append("")
            if doc.classes:
                lines.append("### Classes")
                lines.append("")
                for cls in doc.classes:
                    lines.append(f"- [`{cls.name}`](#{cls.name.lower()})")
                lines.append("")
            if doc.functions:
                lines.append("### Functions")
                lines.append("")
                for func in doc.functions:
                    lines.append(f"- [`{func.name}`](#{func.name.lower()})")
                lines.append("")

        # Classes
        for cls in doc.classes:
            lines.append(self.format_class(cls))
            lines.append("")

        # Functions
        for func in doc.functions:
            lines.append(self.format_function(func))
            lines.append("")

        # Constants
        if doc.constants:
            lines.append("## Constants")
            lines.append("")
            for const in doc.constants:
                type_str = f": `{const.type_hint}`" if const.type_hint else ""
                lines.append(f"- `{const.name}`{type_str}")
            lines.append("")

        return "\n".join(lines)

    def format_class(self, doc: ClassDoc) -> str:
        """Format class documentation as Markdown."""
        lines = []

        # Header
        lines.append(f"## Class: `{doc.name}`")
        lines.append("")

        # Inheritance
        if doc.bases:
            lines.append(f"**Inherits from:** {', '.join(f'`{b}`' for b in doc.bases)}")
            lines.append("")

        # Summary
        if doc.summary:
            lines.append(doc.summary)
            lines.append("")

        # Description
        if doc.description:
            lines.append(doc.description)
            lines.append("")

        # Attributes
        if doc.attributes:
            lines.append("### Attributes")
            lines.append("")
            for attr in doc.attributes:
                type_str = f" (`{attr.type_hint}`)" if attr.type_hint else ""
                desc = f" - {attr.description}" if attr.description else ""
                lines.append(f"- **{attr.name}**{type_str}{desc}")
            lines.append("")

        # Properties
        if doc.properties:
            lines.append("### Properties")
            lines.append("")
            for prop in doc.properties:
                lines.append(f"#### `{prop.name}`")
                if prop.summary:
                    lines.append(prop.summary)
                lines.append("")

        # Methods
        if doc.methods:
            lines.append("### Methods")
            lines.append("")
            for method in doc.methods:
                lines.append(self._format_method(method))
                lines.append("")

        # Class methods
        if doc.class_methods:
            lines.append("### Class Methods")
            lines.append("")
            for method in doc.class_methods:
                lines.append(self._format_method(method))
                lines.append("")

        # Static methods
        if doc.static_methods:
            lines.append("### Static Methods")
            lines.append("")
            for method in doc.static_methods:
                lines.append(self._format_method(method))
                lines.append("")

        return "\n".join(lines)

    def format_function(self, doc: FunctionDoc) -> str:
        """Format function documentation as Markdown."""
        lines = []

        # Header with signature
        async_prefix = "async " if doc.is_async else ""
        lines.append(f"## `{async_prefix}{doc.name}{doc.signature}`")
        lines.append("")

        # Summary
        if doc.summary:
            lines.append(doc.summary)
            lines.append("")

        # Description
        if doc.description:
            lines.append(doc.description)
            lines.append("")

        # Parameters
        if doc.parameters:
            lines.append("**Parameters:**")
            lines.append("")
            for param in doc.parameters:
                type_str = f" (`{param.type_hint}`)" if param.type_hint else ""
                default = f", default: `{param.default}`" if param.default else ""
                desc = f" - {param.description}" if param.description else ""
                lines.append(f"- **{param.name}**{type_str}{default}{desc}")
            lines.append("")

        # Returns
        if doc.returns or doc.return_type:
            lines.append("**Returns:**")
            lines.append("")
            type_str = f"`{doc.return_type}` - " if doc.return_type else ""
            lines.append(f"{type_str}{doc.returns}")
            lines.append("")

        # Raises
        if doc.raises:
            lines.append("**Raises:**")
            lines.append("")
            for exc in doc.raises:
                lines.append(f"- {exc}")
            lines.append("")

        # Examples
        if doc.examples:
            lines.append("**Examples:**")
            lines.append("")
            for example in doc.examples:
                lines.append("```python")
                lines.append(example)
                lines.append("```")
                lines.append("")

        return "\n".join(lines)

    def _format_method(self, doc: FunctionDoc) -> str:
        """Format a method as Markdown."""
        lines = []

        async_prefix = "async " if doc.is_async else ""
        lines.append(f"#### `{async_prefix}{doc.name}{doc.signature}`")
        lines.append("")

        if doc.summary:
            lines.append(doc.summary)
            lines.append("")

        if doc.parameters:
            for param in doc.parameters:
                type_str = f" (`{param.type_hint}`)" if param.type_hint else ""
                desc = f" - {param.description}" if param.description else ""
                lines.append(f"- **{param.name}**{type_str}{desc}")
            lines.append("")

        return "\n".join(lines)

    def format_package(self, doc: PackageDoc) -> str:
        """Format package documentation as Markdown."""
        lines = []

        lines.append(f"# Package: `{doc.name}`")
        lines.append("")

        if doc.summary:
            lines.append(doc.summary)
            lines.append("")

        if doc.description:
            lines.append(doc.description)
            lines.append("")

        # Modules
        if doc.modules:
            lines.append("## Modules")
            lines.append("")
            for module in doc.modules:
                summary = f" - {module.summary}" if module.summary else ""
                lines.append(f"- [`{module.name}`]({module.name}.md){summary}")
            lines.append("")

        # Subpackages
        if doc.subpackages:
            lines.append("## Subpackages")
            lines.append("")
            for pkg in doc.subpackages:
                summary = f" - {pkg.summary}" if pkg.summary else ""
                lines.append(f"- [`{pkg.name}`]({pkg.name}/index.md){summary}")
            lines.append("")

        return "\n".join(lines)


class HTMLFormatter(DocFormatter):
    """Format documentation as HTML."""

    def __init__(self, css_class_prefix: str = "doc"):
        self._prefix = css_class_prefix

    def format_module(self, doc: ModuleDoc) -> str:
        """Format module documentation as HTML."""
        html = []

        html.append(f'<div class="{self._prefix}-module">')
        html.append(
            f'<h1 class="{self._prefix}-title">Module: <code>{doc.name}</code></h1>'
        )

        if doc.summary:
            html.append(
                f'<p class="{self._prefix}-summary">{self._escape(doc.summary)}</p>'
            )

        if doc.description:
            html.append(
                f'<div class="{self._prefix}-description">{self._escape(doc.description)}</div>'
            )

        # Classes
        for cls in doc.classes:
            html.append(self.format_class(cls))

        # Functions
        for func in doc.functions:
            html.append(self.format_function(func))

        html.append("</div>")

        return "\n".join(html)

    def format_class(self, doc: ClassDoc) -> str:
        """Format class documentation as HTML."""
        html = []

        html.append(f'<div class="{self._prefix}-class" id="{doc.name.lower()}">')
        html.append(f"<h2>Class: <code>{doc.name}</code></h2>")

        if doc.bases:
            bases = ", ".join(f"<code>{b}</code>" for b in doc.bases)
            html.append(f'<p class="{self._prefix}-bases">Inherits from: {bases}</p>')

        if doc.summary:
            html.append(
                f'<p class="{self._prefix}-summary">{self._escape(doc.summary)}</p>'
            )

        # Methods
        if doc.methods:
            html.append(f'<div class="{self._prefix}-methods">')
            html.append("<h3>Methods</h3>")
            for method in doc.methods:
                html.append(self._format_method_html(method))
            html.append("</div>")

        html.append("</div>")

        return "\n".join(html)

    def format_function(self, doc: FunctionDoc) -> str:
        """Format function documentation as HTML."""
        html = []

        async_prefix = "async " if doc.is_async else ""
        html.append(f'<div class="{self._prefix}-function" id="{doc.name.lower()}">')
        html.append(
            f"<h2><code>{async_prefix}{doc.name}{self._escape(doc.signature)}</code></h2>"
        )

        if doc.summary:
            html.append(
                f'<p class="{self._prefix}-summary">{self._escape(doc.summary)}</p>'
            )

        if doc.parameters:
            html.append(f'<div class="{self._prefix}-params">')
            html.append("<h4>Parameters</h4>")
            html.append("<ul>")
            for param in doc.parameters:
                type_str = (
                    f" (<code>{param.type_hint}</code>)" if param.type_hint else ""
                )
                desc = (
                    f" - {self._escape(param.description)}" if param.description else ""
                )
                html.append(f"<li><strong>{param.name}</strong>{type_str}{desc}</li>")
            html.append("</ul>")
            html.append("</div>")

        if doc.returns:
            html.append(f'<div class="{self._prefix}-returns">')
            html.append("<h4>Returns</h4>")
            html.append(f"<p>{self._escape(doc.returns)}</p>")
            html.append("</div>")

        html.append("</div>")

        return "\n".join(html)

    def _format_method_html(self, doc: FunctionDoc) -> str:
        """Format a method as HTML."""
        async_prefix = "async " if doc.is_async else ""
        html = f'<div class="{self._prefix}-method">'
        html += f"<h4><code>{async_prefix}{doc.name}{self._escape(doc.signature)}</code></h4>"
        if doc.summary:
            html += f"<p>{self._escape(doc.summary)}</p>"
        html += "</div>"
        return html

    def format_package(self, doc: PackageDoc) -> str:
        """Format package documentation as HTML."""
        html = []

        html.append(f'<div class="{self._prefix}-package">')
        html.append(f"<h1>Package: <code>{doc.name}</code></h1>")

        if doc.summary:
            html.append(
                f'<p class="{self._prefix}-summary">{self._escape(doc.summary)}</p>'
            )

        if doc.modules:
            html.append("<h2>Modules</h2>")
            html.append("<ul>")
            for module in doc.modules:
                html.append(f'<li><a href="{module.name}.html">{module.name}</a></li>')
            html.append("</ul>")

        html.append("</div>")

        return "\n".join(html)

    def _escape(self, text: str) -> str:
        """Escape HTML special characters."""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )


class JSONFormatter(DocFormatter):
    """Format documentation as JSON."""

    def __init__(self, indent: int = 2):
        self._indent = indent

    def format_module(self, doc: ModuleDoc) -> str:
        """Format module documentation as JSON."""
        return json.dumps(doc.to_dict(), indent=self._indent)

    def format_class(self, doc: ClassDoc) -> str:
        """Format class documentation as JSON."""
        return json.dumps(doc.to_dict(), indent=self._indent)

    def format_function(self, doc: FunctionDoc) -> str:
        """Format function documentation as JSON."""
        return json.dumps(doc.to_dict(), indent=self._indent)

    def format_package(self, doc: PackageDoc) -> str:
        """Format package documentation as JSON."""
        return json.dumps(doc.to_dict(), indent=self._indent)


class RSTFormatter(DocFormatter):
    """Format documentation as reStructuredText."""

    def format_module(self, doc: ModuleDoc) -> str:
        """Format module documentation as RST."""
        lines = []

        # Title
        title = f"Module: {doc.name}"
        lines.append("=" * len(title))
        lines.append(title)
        lines.append("=" * len(title))
        lines.append("")

        if doc.summary:
            lines.append(doc.summary)
            lines.append("")

        if doc.description:
            lines.append(doc.description)
            lines.append("")

        # Classes
        for cls in doc.classes:
            lines.append(self.format_class(cls))
            lines.append("")

        # Functions
        for func in doc.functions:
            lines.append(self.format_function(func))
            lines.append("")

        return "\n".join(lines)

    def format_class(self, doc: ClassDoc) -> str:
        """Format class documentation as RST."""
        lines = []

        title = f"Class: {doc.name}"
        lines.append(title)
        lines.append("-" * len(title))
        lines.append("")

        if doc.bases:
            lines.append(f"**Inherits from:** {', '.join(doc.bases)}")
            lines.append("")

        if doc.summary:
            lines.append(doc.summary)
            lines.append("")

        # Methods
        if doc.methods:
            lines.append("Methods")
            lines.append("^" * 7)
            lines.append("")
            for method in doc.methods:
                lines.append(self._format_method_rst(method))
                lines.append("")

        return "\n".join(lines)

    def format_function(self, doc: FunctionDoc) -> str:
        """Format function documentation as RST."""
        lines = []

        async_prefix = "async " if doc.is_async else ""
        lines.append(f".. py:function:: {async_prefix}{doc.name}{doc.signature}")
        lines.append("")

        if doc.summary:
            lines.append(f"   {doc.summary}")
            lines.append("")

        for param in doc.parameters:
            type_str = f" ({param.type_hint})" if param.type_hint else ""
            lines.append(f"   :param {param.name}{type_str}: {param.description}")

        if doc.return_type:
            lines.append(f"   :rtype: {doc.return_type}")

        if doc.returns:
            lines.append(f"   :returns: {doc.returns}")

        lines.append("")

        return "\n".join(lines)

    def _format_method_rst(self, doc: FunctionDoc) -> str:
        """Format a method as RST."""
        lines = []
        async_prefix = "async " if doc.is_async else ""
        lines.append(f".. py:method:: {async_prefix}{doc.name}{doc.signature}")
        lines.append("")
        if doc.summary:
            lines.append(f"   {doc.summary}")
        lines.append("")
        return "\n".join(lines)

    def format_package(self, doc: PackageDoc) -> str:
        """Format package documentation as RST."""
        lines = []

        title = f"Package: {doc.name}"
        lines.append("=" * len(title))
        lines.append(title)
        lines.append("=" * len(title))
        lines.append("")

        if doc.summary:
            lines.append(doc.summary)
            lines.append("")

        if doc.modules:
            lines.append("Modules")
            lines.append("-" * 7)
            lines.append("")
            lines.append(".. toctree::")
            lines.append("   :maxdepth: 2")
            lines.append("")
            for module in doc.modules:
                lines.append(f"   {module.name}")
            lines.append("")

        return "\n".join(lines)


class DocumentationGenerator:
    """Main documentation generator class."""

    def __init__(
        self,
        output_format: OutputFormat = OutputFormat.MARKDOWN,
        include_private: bool = False,
        include_source_links: bool = False,
    ):
        """Initialize documentation generator."""
        self._format = output_format
        self._include_private = include_private
        self._analyzer = CodeAnalyzer()
        self._formatter = self._create_formatter(output_format, include_source_links)

    def _create_formatter(
        self, output_format: OutputFormat, include_source_links: bool
    ) -> DocFormatter:
        """Create the appropriate formatter."""
        if output_format == OutputFormat.MARKDOWN:
            return MarkdownFormatter(include_source_links=include_source_links)
        elif output_format == OutputFormat.HTML:
            return HTMLFormatter()
        elif output_format == OutputFormat.JSON:
            return JSONFormatter()
        elif output_format == OutputFormat.RST:
            return RSTFormatter()
        else:
            raise ValueError(f"Unsupported format: {output_format}")

    def generate_module_docs(self, module_path: Path) -> str:
        """Generate documentation for a single module file."""
        doc = self._analyzer.analyze_module(module_path)
        return self._formatter.format_module(doc)

    def generate_module_docs_from_object(self, module: Any) -> str:
        """Generate documentation from a loaded module object."""
        doc = self._analyzer.analyze_module_object(module)
        return self._formatter.format_module(doc)

    def generate_package_docs(
        self,
        package_path: Path,
        output_dir: Optional[Path] = None,
    ) -> Dict[str, str]:
        """Generate documentation for a package."""
        docs = {}

        # Find all Python files
        for py_file in package_path.rglob("*.py"):
            if py_file.name.startswith("_") and py_file.name != "__init__.py":
                if not self._include_private:
                    continue

            relative_path = py_file.relative_to(package_path)
            doc_name = str(relative_path).replace(".py", "").replace("/", ".")

            try:
                doc = self._analyzer.analyze_module(py_file)
                docs[doc_name] = self._formatter.format_module(doc)
            except Exception as e:
                docs[doc_name] = f"Error generating docs: {e}"

        # Write to output directory if specified
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            extension = self._get_extension()

            for name, content in docs.items():
                output_file = output_dir / f"{name}{extension}"
                output_file.parent.mkdir(parents=True, exist_ok=True)
                output_file.write_text(content)

        return docs

    def generate_class_docs(self, cls: Type) -> str:
        """Generate documentation for a class."""
        doc = self._analyzer._analyze_class_object(cls)
        return self._formatter.format_class(doc)

    def generate_function_docs(self, func: Callable) -> str:
        """Generate documentation for a function."""
        doc = self._analyzer._analyze_function_object(func)
        return self._formatter.format_function(doc)

    def _get_extension(self) -> str:
        """Get file extension for output format."""
        extensions = {
            OutputFormat.MARKDOWN: ".md",
            OutputFormat.HTML: ".html",
            OutputFormat.JSON: ".json",
            OutputFormat.RST: ".rst",
        }
        return extensions.get(self._format, ".txt")


def generate_docs(
    source: Union[Path, Any],
    output_format: OutputFormat = OutputFormat.MARKDOWN,
    output_path: Optional[Path] = None,
) -> str:
    """Generate documentation from source.

    Args:
        source: Path to module/package or module object
        output_format: Output format (markdown, html, json, rst)
        output_path: Optional path to write output

    Returns:
        Generated documentation string
    """
    generator = DocumentationGenerator(output_format=output_format)

    if isinstance(source, Path):
        if source.is_dir():
            docs = generator.generate_package_docs(source, output_path)
            return "\n\n".join(docs.values())
        else:
            content = generator.generate_module_docs(source)
    else:
        content = generator.generate_module_docs_from_object(source)

    if output_path:
        output_path.write_text(content)

    return content
