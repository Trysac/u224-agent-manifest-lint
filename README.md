# agent-manifest-lint

Lint agent manifests for least privilege. The linter checks required fields, wildcard and sensitive permissions, tool permissions that the agent did not declare, unused grants, duplicate tool names, short tool descriptions, and inline secrets in env entries. Every finding carries a rule id, a severity, an RFC 6901 JSON Pointer, and a message.

## Manifest format

The input is a JSON object:

- `name`: string matching `^[a-z0-9]+(?:-[a-z0-9]+)*$`, 1 to 64 characters.
- `version`: string matching Semantic Versioning 2.0.0.
- `description`: string of 1 to 1024 characters.
- `permissions`: array of permission strings.
- `tools`: array of 1 to 128 objects. Each object has `name` (matching `^[a-z][a-z0-9_]{0,63}$`), `description` (string), and `permissions` (array of permission strings).
- `env` (optional): array of environment variable names, each matching `^[A-Z][A-Z0-9_]*$`.

Permission strings have one of these forms:

- `fs:read:<path>` or `fs:write:<path>`, where `<path>` starts with `/`.
- `net:<host>`, where `<host>` matches `^[a-z0-9.-]+$` or is `*`.
- `shell:<command>`, where `<command>` matches `^[a-z0-9._-]+$` or is `*`.
- `env:<NAME>`, where `<NAME>` matches `^[A-Z][A-Z0-9_]*$`.

## Rules

- `AM001` (error): a required field is missing or invalid, `tools` is empty or has more than 128 entries, or a tool object is invalid.
- `AM002` (error): a manifest-level permission has `*` in its value, or is `fs:read:/` or `fs:write:/`.
- `AM003` (error): a tool permission is not exactly equal to a manifest-level permission.
- `AM004` (warning): a manifest-level permission is not used by any tool.
- `AM005` (error): a tool name is duplicated; the pointer is the later occurrence.
- `AM006` (error): an `env` entry is not a valid environment variable name. An entry containing `=` produces `env entry must be a variable name, not a value`; the value is never echoed.
- `AM007` (error): a permission is not a string or has invalid syntax. The message quotes at most 64 characters.
- `AM008` (error): an `fs:write` permission targets `/`, `/etc`, `/usr`, `/bin`, `/sbin`, `/boot`, `/sys`, `/proc`, `/root`, anything under those paths, a path with a `..` segment, or a path containing `/.ssh`. Paths are normalised first, so `//etc/passwd` and `/./etc/passwd` are caught.
- `AM009` (warning): a tool description is shorter than 10 characters.

Findings are sorted by pointer in document order, then by rule. Pointers escape `~` as `~0` and `/` as `~1`.

## Installation

Python 3.10 or newer is required. The package has no runtime dependencies. From a source checkout:

```sh
python -m pip install .
```

## Usage

Library:

```python
from agent_manifest_lint import format_text, lint

manifest = {
    "name": "triage-bot",
    "version": "1.2.0",
    "description": "Triage support tickets.",
    "permissions": ["net:api.example.com"],
    "tools": [
        {"name": "search", "description": "Search tickets.", "permissions": ["net:api.example.com"]}
    ],
    "env": ["API_TOKEN"],
}
print(format_text(lint(manifest)))
```

Command line:

```console
$ agent-manifest-lint manifest.json
$ agent-manifest-lint --format json manifest.json
```

The CLI accepts one path and `--format {text,json}` (default `text`). It uses `lint_text` defaults: `max_bytes=1_048_576` and `max_depth=32`. Exit codes: `0` when there are no findings or only warnings, `1` when at least one error is found, `2` on usage, I/O, or invalid JSON errors.

## Public API

- `lint(manifest: Mapping[str, Any]) -> list[Finding]`: validates a parsed mapping and returns findings sorted by pointer then rule.
- `lint_text(text: str | bytes, *, max_bytes: int = 1_048_576, max_depth: int = 32) -> list[Finding]`: parses UTF-8 JSON and calls `lint`. It rejects a BOM, invalid UTF-8, duplicate object keys, a top-level value that is not an object, input larger than `max_bytes`, and nesting deeper than `max_depth`. It raises `LintError` with code `invalid_json`, `too_large`, or `too_deep`.
- `Finding`: frozen dataclass with fields `rule: str`, `severity: Literal["error", "warning"]`, `pointer: str`, and `message: str`.
- `format_text(findings: Sequence[Finding]) -> str`: returns one line per finding as `<rule> <severity> <pointer> <message>`, with quote characters removed from the message.
- `LintError(code: Literal["invalid_json", "too_large", "too_deep"], message: str = "")`: string form is `code: message`.
- `__version__`: `0.1.0`.

## Why not schema validation alone

A schema can check shapes and field types. This linter also checks relations between grants and tools: every tool permission must be declared by the agent, every agent permission should be used, wildcards and root file-system grants are rejected, sensitive write paths are rejected, and env entries are checked for pasted values.

## Security

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and limits.

## Development

Tests live in `tests/test_agent_manifest_lint.py` and use `pytest`. Run them with:

```sh
pytest
```
