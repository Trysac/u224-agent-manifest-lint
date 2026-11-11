# Architecture

## Overview

The linter is a pure function library that validates a manifest mapping against a set of least-privilege rules. It is deliberately schemaless beyond the documented format, focusing on relationships between declared permissions and tool usage rather than exhaustive schema validation.

## Key components

- **`lint(manifest)`**: Core validation, returns sorted findings.
- **`lint_text(text)`**: Handles JSON parsing with size/depth limits and duplicate-key rejection.
- **`Finding`**: Immutable dataclass holding rule, severity, pointer, and message.
- **`LintError`**: Typed exception for parse/limit errors.
- **`format_text`**: Human-readable output.
- **CLI (`__main__.py`)**: Thin wrapper around `lint_text`.

Findings are sorted by JSON Pointer (document order) and then rule. Pointer generation follows RFC 6901.

The linter also enforces limits: maximum 1 MiB input, maximum 32 levels of nesting, and rejects BOM and duplicate keys.
