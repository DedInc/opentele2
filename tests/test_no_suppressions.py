from __future__ import annotations

import ast
import io
import re
import subprocess
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Agent-tooling tests are untracked and outside the library's lint contract.
EXCLUDED_TESTS = frozenset(
    {
        "test_no_suppressions.py",
        "test_agentctl.py",
        "test_audit_remediation.py",
        "test_control_plane.py",
        "test_guard_bypasses.py",
        "test_install.py",
        "test_market_routing.py",
        "test_model_routing.py",
    }
)

MARKER = re.compile(
    r"\bnoqa\b"
    r"|\btype:\s*ignore\b"
    r"|\bty:\s*ignore\b"
    r"|\bpyright:\s*ignore\b"
    r"|\bnocov\b"
    r"|\bpragma:\s*no\s*cover\b",
    re.IGNORECASE,
)


def _tracked_python_files() -> list[Path]:
    listed = subprocess.run(
        ["git", "ls-files", "--", "src", "tests"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    return sorted(ROOT / rel for rel in listed if _in_scope(Path(rel)))


def _in_scope(path: Path) -> bool:
    if path.suffix != ".py":
        return False
    if path.parts[0] == "src":
        return True
    is_library_test = path.name.startswith("test_") or path.name == "tdata_test.py"
    return len(path.parts) == 2 and is_library_test and path.name not in EXCLUDED_TESTS


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


def test_scan_covers_src_and_library_tests() -> None:
    files = _tracked_python_files()
    names = {path.name for path in files}
    assert any(path.relative_to(ROOT).parts[0] == "src" for path in files)
    assert "test_full.py" in names
    assert "tdata_test.py" in names
    assert names.isdisjoint(EXCLUDED_TESTS)


def test_no_suppressions_in_src_or_library_tests() -> None:
    found = [hit for path in _tracked_python_files() for hit in find_suppressions(path)]
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
        "import typing\n"
        "from typing import cast\n"
        "a = cast(int, 1)\n"
        "b = typing.cast(int, 2)\n",
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
