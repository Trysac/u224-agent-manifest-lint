"""Tests for agent_manifest_lint."""

from __future__ import annotations

import json
from typing import Any

import pytest

from agent_manifest_lint import (
    Finding,
    LintError,
    _build_pointer,
    format_text,
    lint,
    lint_text,
)
from agent_manifest_lint.__main__ import main


def _valid_manifest() -> dict[str, Any]:
    return {
        "name": "triage-bot",
        "version": "1.2.0",
        "description": "Triage support tickets.",
        "permissions": ["net:api.example.com"],
        "tools": [
            {
                "name": "search",
                "description": "Search tickets.",
                "permissions": ["net:api.example.com"],
            }
        ],
        "env": ["API_TOKEN"],
    }


def _manifest(**overrides: Any) -> dict[str, Any]:
    m = _valid_manifest()
    m.update(overrides)
    return m


# ---------------------------------------------------------------------------
# Acceptance tests (verbatim)
# ---------------------------------------------------------------------------


def test_valid_manifest_returns_empty() -> None:
    assert lint(_valid_manifest()) == []


def test_am002_wildcard_manifest_permission() -> None:
    manifest = _valid_manifest()
    manifest["permissions"] = ["net:*"]
    manifest["tools"][0]["permissions"] = ["net:*"]
    findings = lint(manifest)
    assert findings == [Finding("AM002", "error", "/permissions/0", "wildcard permission 'net:*'")]


def test_am003_tool_permission_not_declared() -> None:
    manifest = _manifest(
        permissions=["fs:read:/data"],
        tools=[
            {
                "name": "search",
                "description": "Search tickets.",
                "permissions": ["fs:read:/data", "fs:write:/tmp/out"],
            }
        ],
    )
    findings = lint(manifest)
    # Expected: AM003 for /tools/0/permissions/1 (index 1)
    assert (
        Finding(
            "AM003",
            "error",
            "/tools/0/permissions/1",
            "tool permission 'fs:write:/tmp/out' is not declared by the agent",
        )
        in findings
    )
    # Ensure no other AM003 for index 0
    am003s = [f for f in findings if f.rule == "AM003"]
    assert len(am003s) == 1
    assert am003s[0].pointer == "/tools/0/permissions/1"


def test_am004_unused_manifest_permission() -> None:
    manifest = _manifest(
        permissions=["fs:read:/a", "fs:read:/data"],
        tools=[
            {
                "name": "reader",
                "description": "Read data.",
                "permissions": ["fs:read:/a"],
            }
        ],
    )
    findings = lint(manifest)
    assert (
        Finding(
            "AM004",
            "warning",
            "/permissions/1",
            "permission 'fs:read:/data' is not used by any tool",
        )
        in findings
    )


def test_am006_inline_secret() -> None:
    manifest = _manifest(env=["API_TOKEN=abc123"])
    findings = lint(manifest)
    assert findings == [
        Finding(
            "AM006",
            "error",
            "/env/0",
            "env entry must be a variable name, not a value",
        )
    ]
    # Ensure no output contains the secret.
    assert "abc123" not in format_text(findings)


def test_am008_fs_write_restricted_and_am007_and_missing_name_and_duplicate_tool() -> None:
    # fs:write:/etc -> AM008
    manifest = _manifest(
        permissions=["fs:write:/etc"],
        tools=[
            {
                "name": "writer",
                "description": "Write files.",
                "permissions": ["fs:write:/etc"],
            }
        ],
    )
    findings = lint(manifest)
    assert any(f.rule == "AM008" and f.pointer == "/permissions/0" for f in findings)

    # fs:write:/data/../etc -> AM008
    manifest = _manifest(
        permissions=["fs:write:/data/../etc"],
        tools=[
            {
                "name": "writer",
                "description": "Write files.",
                "permissions": ["fs:write:/data/../etc"],
            }
        ],
    )
    findings = lint(manifest)
    assert any(f.rule == "AM008" and f.pointer == "/permissions/0" for f in findings)

    # disk:read:/x -> AM007
    manifest = _manifest(
        permissions=["disk:read:/x"],
        tools=[
            {
                "name": "tool",
                "description": "A tool.",
                "permissions": ["disk:read:/x"],
            }
        ],
    )
    findings = lint(manifest)
    assert any(f.rule == "AM007" and f.pointer == "/permissions/0" for f in findings)

    # missing name -> AM001
    manifest = _manifest()
    del manifest["name"]
    findings = lint(manifest)
    assert Finding("AM001", "error", "/name", "missing required field name") in findings

    # duplicate tool names -> AM005 at /tools/1/name
    manifest = _manifest(
        tools=[
            {
                "name": "search",
                "description": "Primary search tool.",
                "permissions": ["net:api.example.com"],
            },
            {
                "name": "search",
                "description": "Secondary search tool.",
                "permissions": ["net:api.example.com"],
            },
        ]
    )
    findings = lint(manifest)
    assert Finding("AM005", "error", "/tools/1/name", "duplicate tool name") in findings


def test_lint_text_errors_and_limits() -> None:
    # invalid JSON
    with pytest.raises(LintError) as exc_info:
        lint_text("not json")
    assert exc_info.value.code == "invalid_json"

    # duplicate key
    with pytest.raises(LintError) as exc_info:
        lint_text('{"a": 1, "a": 2}')
    assert exc_info.value.code == "invalid_json"

    # too large
    with pytest.raises(LintError) as exc_info:
        lint_text(b"{}", max_bytes=1)
    assert exc_info.value.code == "too_large"

    # Boundary: exactly 1 048 576 bytes passes the size check, one more does not.
    limit = 1_048_576
    exact = b"[" + b" " * (limit - 2) + b"]"
    assert len(exact) == limit
    with pytest.raises(LintError) as exc_info:
        lint_text(exact + b" ", max_bytes=limit)
    assert exc_info.value.code == "too_large"
    # Exactly at the limit the size check passes and only parsing fails.
    with pytest.raises(LintError) as exc_info:
        lint_text(exact, max_bytes=limit)
    assert exc_info.value.code == "invalid_json"

    # A small valid manifest is accepted at its own size.
    valid_json = (
        '{"name":"a","version":"1.0.0","description":"desc","permissions":[],'
        '"tools":[{"name":"t","description":"tool description","permissions":[]}]}'
    )
    valid_bytes = valid_json.encode("utf-8")
    assert lint_text(valid_bytes, max_bytes=len(valid_bytes)) == []

    # too deep
    nested = {}
    current = nested
    for _ in range(33):
        current["a"] = {}
        current = current["a"]
    deep_json = json.dumps(nested)
    with pytest.raises(LintError) as exc_info:
        lint_text(deep_json)
    assert exc_info.value.code == "too_deep"

    # BOM rejected
    with pytest.raises(LintError) as exc_info:
        lint_text(b"\xef\xbb\xbf{}")
    assert exc_info.value.code == "invalid_json"


def test_lint_text_adversarial_nesting_is_too_deep() -> None:
    # More nesting than the interpreter recursion limit: parsing must not leak
    # a RecursionError, it must surface as LintError("too_deep").
    with pytest.raises(LintError) as exc_info:
        lint_text(b"[" * 5000)
    assert exc_info.value.code == "too_deep"


def test_am002_wildcard_in_shell_and_fs_values() -> None:
    manifest = _manifest(
        permissions=["shell:*"],
        tools=[
            {
                "name": "shell_tool",
                "description": "Run any command.",
                "permissions": ["shell:*"],
            }
        ],
        env=[],
    )
    findings = lint(manifest)
    assert Finding("AM002", "error", "/permissions/0", "wildcard permission 'shell:*'") in findings

    manifest = _manifest(
        permissions=["fs:write:/data/*"],
        tools=[
            {
                "name": "writer",
                "description": "Write everything under data.",
                "permissions": ["fs:write:/data/*"],
            }
        ],
        env=[],
    )
    findings = lint(manifest)
    assert (
        Finding("AM002", "error", "/permissions/0", "wildcard permission 'fs:write:/data/*'")
        in findings
    )


def test_am004_pointer_uses_original_index() -> None:
    manifest = _manifest(
        permissions=["disk:read:/x", "fs:read:/data"],
        tools=[
            {
                "name": "reader",
                "description": "Reads nothing declared.",
                "permissions": [],
            }
        ],
    )
    findings = lint(manifest)
    assert any(f.rule == "AM007" and f.pointer == "/permissions/0" for f in findings)
    am004s = [f for f in findings if f.rule == "AM004"]
    assert len(am004s) == 1
    assert am004s[0].pointer == "/permissions/1"


def test_am008_normalised_paths_are_restricted() -> None:
    for path in ("//etc/passwd", "/./etc/passwd"):
        manifest = _manifest(
            permissions=[f"fs:write:{path}"],
            tools=[
                {
                    "name": "writer",
                    "description": "Write files.",
                    "permissions": [f"fs:write:{path}"],
                }
            ],
        )
        findings = lint(manifest)
        assert any(f.rule == "AM008" and f.pointer == "/permissions/0" for f in findings), path


def test_format_text_removes_quotes() -> None:
    findings = [
        Finding(
            "AM002",
            "error",
            "/permissions/0",
            "wildcard permission 'net:*'",
        )
    ]
    result = format_text(findings)
    assert result == "AM002 error /permissions/0 wildcard permission net:*"


def test_pointer_escaping() -> None:
    # Directly test _build_pointer
    assert _build_pointer(["a/b", "c~d"]) == "/a~1b/c~0d"


def test_empty_tools_array_am001() -> None:
    manifest = _manifest(tools=[])
    findings = lint(manifest)
    assert any(f.rule == "AM001" and f.pointer == "/tools" for f in findings)


def test_permissions_not_strings_am007() -> None:
    manifest = _manifest(permissions=[123])
    findings = lint(manifest)
    assert any(f.rule == "AM007" and f.pointer == "/permissions/0" for f in findings)


def test_env_absent_ok() -> None:
    manifest = _valid_manifest()
    del manifest["env"]
    findings = lint(manifest)
    assert findings == []


def test_main_text_and_json_output(tmp_path, capsys) -> None:
    # Valid manifest -> exit 0, no output
    p = tmp_path / "good.json"
    p.write_text(json.dumps(_valid_manifest()))
    exit_code = main([str(p)])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == "\n"  # empty line from print of empty string

    # Manifest with error -> exit 1, text output
    bad = _valid_manifest()
    bad["permissions"] = ["net:*"]
    bad["tools"][0]["permissions"] = ["net:*"]
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(bad))
    exit_code = main([str(p)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "AM002 error /permissions/0 wildcard permission net:*" in captured.out

    # Invalid JSON -> exit 2
    p = tmp_path / "invalid.json"
    p.write_text("not json")
    exit_code = main([str(p)])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Error:" in captured.err

    # --format json
    p = tmp_path / "json.json"
    p.write_text(json.dumps(bad))
    exit_code = main([str(p), "--format", "json"])
    captured = capsys.readouterr()
    assert exit_code == 1
    parsed = json.loads(captured.out)
    assert isinstance(parsed, list)
    assert len(parsed) > 0
    # Check sorted keys
    first = parsed[0]
    assert set(first.keys()) == {"rule", "severity", "pointer", "message"}
    # Ensure alphabetical order in JSON (sort_keys)
    keys = list(first.keys())
    assert keys == sorted(keys)

    # Missing file -> exit 2
    exit_code = main([str(tmp_path / "nonexistent.json")])
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "Error reading file" in captured.err

    # Invalid --format -> argparse SystemExit caught -> exit 2
    exit_code = main([str(p), "--format", "yaml"])
    captured = capsys.readouterr()
    assert exit_code == 2


def test_am002_root_fs_read_write() -> None:
    # fs:read:/ and fs:write:/ trigger AM002 and AM008 (for write)
    manifest = _manifest(
        permissions=["fs:read:/", "fs:write:/"],
        tools=[
            {
                "name": "root",
                "description": "Root access.",
                "permissions": ["fs:read:/", "fs:write:/"],
            }
        ],
    )
    findings = lint(manifest)
    am002s = [f for f in findings if f.rule == "AM002"]
    assert len(am002s) == 2
    assert all(f.severity == "error" for f in am002s)
    am008s = [f for f in findings if f.rule == "AM008"]
    assert len(am008s) == 2  # both write: for manifest and tool? Actually tool write also AM008
    # The manifest and tool both declare fs:write:/, so two AM008 findings (manifest-level and tool-level)
    assert any(f.pointer == "/permissions/1" for f in am008s)
    assert any(f.pointer == "/tools/0/permissions/1" for f in am008s)


def test_tool_description_short_warning() -> None:
    manifest = _manifest(
        tools=[
            {
                "name": "tool",
                "description": "short",
                "permissions": ["net:api.example.com"],
            }
        ]
    )
    findings = lint(manifest)
    assert any(f.rule == "AM009" and f.severity == "warning" for f in findings)


def test_tools_over_128_am001() -> None:
    tools = [
        {
            "name": f"tool{i}",
            "description": "description enough",
            "permissions": [],
        }
        for i in range(129)
    ]
    manifest = _manifest(tools=tools)
    findings = lint(manifest)
    assert any(f.rule == "AM001" and f.pointer == "/tools" for f in findings)


def test_main_manifest_json_one_line_per_finding(tmp_path, capsys, monkeypatch) -> None:
    # Acceptance: main(['manifest.json']) prints one line per finding.
    bad = _valid_manifest()
    bad["permissions"] = ["net:*"]
    bad["tools"][0]["permissions"] = ["net:*"]
    (tmp_path / "manifest.json").write_text(json.dumps(bad))
    monkeypatch.chdir(tmp_path)
    exit_code = main(["manifest.json"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == "AM002 error /permissions/0 wildcard permission net:*\n"
