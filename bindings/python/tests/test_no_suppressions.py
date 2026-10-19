"""The 1.5.0 no-suppression rule (1.5.0 tests/test_no_suppressions.py),
retargeted at the new package: no ``noqa``, ``type: ignore``, ``ty: ignore``,
``pyright: ignore``, ``nocov`` or ``pragma: no cover`` comment and no
``cast(`` call in bindings/python/python or bindings/python/tests.

Files are found on disk rather than through ``git ls-files``, so a new,
not yet tracked file is held to the rule too."""

from __future__ import annotations

import ast
import io
import re
import tokenize
from pathlib import Path

BINDING = Path(__file__).resolve().parents[1]
SCANNED_DIRS = (BINDING / "python", BINDING / "tests")

MARKER = re.compile(
    r"\bnoqa\b"
    r"|\btype:\s*ignore\b"
    r"|\bty:\s*ignore\b"
    r"|\bpyright:\s*ignore\b"
    r"|\bnocov\b"
    r"|\bpragma:\s*no\s*cover\b",
    re.IGNORECASE,
)


def _scanned_files() -> list[Path]:
    found = [
        path
        for root in SCANNED_DIRS
        for pattern in ("*.py", "*.pyi")
        for path in root.rglob(pattern)
        if "__pycache__" not in path.parts
    ]
    return sorted(found)


def _is_cast_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id == "cast"
    if isinstance(func, ast.Attribute) and func.attr == "cast":
        return isinstance(func.value, ast.Name) and func.value.id == "typing"
    return False


def find_suppressions(path: Path) -> list[str]:
    source = path.read_text(encoding="utf-8")
    hits: list[tuple[int, str]] = []
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    for token in tokens:
        if token.type == tokenize.COMMENT and MARKER.search(token.string):
            hits.append((token.start[0], token.string.strip()))
    for node in ast.walk(ast.parse(source, filename=str(path))):
        if isinstance(node, ast.Call) and _is_cast_call(node):
            hits.append((node.lineno, "cast( call"))
    return [f"{path}:{line}: {what}" for line, what in sorted(hits)]


def test_scan_covers_the_package_and_its_tests() -> None:
    files = _scanned_files()
    relative = {path.relative_to(BINDING).as_posix() for path in files}
    assert "python/opentele2/__init__.py" in relative
    assert "python/opentele2/_native.pyi" in relative
    assert "python/opentele2/td/tdesktop.py" in relative
    assert "python/opentele2/tl/telethon.py" in relative
    assert "tests/conftest.py" in relative
    assert "tests/test_no_suppressions.py" in relative
    assert all("__pycache__" not in path.parts for path in files)


def test_no_suppressions_in_the_package_or_its_tests() -> None:
    found = [hit for path in _scanned_files() for hit in find_suppressions(path)]
    assert not found, "suppressions found:\n" + "\n".join(found)


def test_scanner_flags_each_comment_marker(tmp_path: Path) -> None:
    markers = [
        "noqa",
        "noqa: E501",
        "type: ignore",
        "type: ignore[assignment]",
        "ty: ignore",
        "pyright: ignore",
        "nocov",
        "pragma: no cover",
    ]
    sample = tmp_path / "sample.py"
    sample.write_text(
        "".join(f"x{n} = 1  # {marker}\n" for n, marker in enumerate(markers)),
        encoding="utf-8",
    )
    found = find_suppressions(sample)
    assert len(found) == len(markers)
    assert found[0] == f"{sample}:1: # noqa"


def test_scanner_flags_cast_calls(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    sample.write_text(
        "import typing\nfrom typing import cast\na = cast(int, 1)\nb = typing.cast(int, 2)\n",
        encoding="utf-8",
    )
    assert find_suppressions(sample) == [
        f"{sample}:3: cast( call",
        f"{sample}:4: cast( call",
    ]


def test_scanner_ignores_markers_inside_strings(tmp_path: Path) -> None:
    sample = tmp_path / "sample.py"
    sample.write_text(
        'a = "x = 1  # noqa"\n'
        "b = '# type: ignore and cast(int, 1)'\n"
        '"""# pragma: no cover"""\n'
        "# plain comment about casting\n",
        encoding="utf-8",
    )
    assert find_suppressions(sample) == []
