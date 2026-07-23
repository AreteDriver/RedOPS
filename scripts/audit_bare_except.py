#!/usr/bin/env python3
"""Audit script for bare 'except Exception' blocks in RedOPS source.

Run: python scripts/audit_bare_except.py
"""

import ast
import sys
from pathlib import Path


def find_bare_except(filepath: Path) -> list[tuple[int, str]]:
    """Find 'except Exception' blocks in a Python file."""
    results = []
    source = filepath.read_text()
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler):
            if isinstance(node.type, ast.Name) and node.type.id == "Exception":
                line = source.splitlines()[node.lineno - 1]
                results.append((node.lineno, line.strip()))

    return results


def main() -> int:
    src_dir = Path(__file__).parent.parent / "src" / "redops"
    total = 0
    files = 0

    for pyfile in sorted(src_dir.rglob("*.py")):
        findings = find_bare_except(pyfile)
        if findings:
            files += 1
            total += len(findings)
            print(f"\n{pyfile.relative_to(src_dir.parent.parent)} ({len(findings)})")
            for lineno, line in findings:
                print(f"  {lineno:4d}: {line}")

    print(f"\n{'=' * 60}")
    print(f"Total: {total} bare 'except Exception' blocks in {files} files")
    print(f"{'=' * 60}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
