# Implement manifest linting as a pure library with a thin CLI

Status: accepted (generated, pending human review)

## Context

Agent manifests are hand-written and reviewed manually, leading to mistakes like overly broad permissions and inline secrets. A linter that checks mechanical rules can catch these before deployment.

## Decision

Implement `agent_manifest_lint` as a Python library with a `lint` function for mappings and a `lint_text` function for JSON parsing, plus a CLI. Findings are represented as immutable `Finding` dataclasses with JSON Pointers, and errors are typed via `LintError`. The linter focuses on relationships between permissions and tools (least privilege) rather than pure schema validation.

## Consequences

The library is dependency-free and can be used in CI or as a pre-commit hook. It enforces size/depth limits and rejects duplicate keys to prevent resource abuse. The CLI provides both text and JSON output. Future extensions can add more rules or support other manifest formats.
