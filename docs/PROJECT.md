# Project record

## Objective

Lint agent manifests for least privilege: required fields, wildcard and sensitive permissions, tool permissions not declared, unused grants and inline secrets, with JSON pointers.

## Scope

- In scope: the `agent_manifest_lint` library (`lint`, `lint_text`, `format_text`, `Finding`, `LintError`, `__version__`), the `agent-manifest-lint` CLI, the documented manifest format, and the nine rules `AM001` through `AM009`.
- In scope: JSON parsing limits in `lint_text` (default 1,048,576 bytes and 32 levels), duplicate-key rejection, BOM rejection, and RFC 6901 pointers.
- Out of scope: A2A Agent Cards, MCP tool schemas, and SKILL.md formats; other linters exist for those formats.
- Out of scope: runtime enforcement of permissions, authentication, sandboxing, command execution, and filesystem or network access.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 1231276 / 79111 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.1059 |

## Factory run u224 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | deepseek-v4-pro | yes | 3579 | 18451 | 0 | 1408 | 0.0389 |
| fix-1 | deepseek-flash | no | 13686 | 4952 | 0 | 98048 | 0.0053 |
| fix-2 | deepseek-flash | no | 9034 | 943 | 0 | 37120 | 0.0020 |
| audit | deepseek-flash | no | 28281 | 22418 | 0 | 412032 | 0.0189 |
| fix-3 | deepseek-flash | no | 28789 | 5992 | 0 | 273536 | 0.0087 |
| threat-model | deepseek-flash | no | 28667 | 13581 | 0 | 222336 | 0.0131 |
| docs | deepseek-flash | no | 74504 | 12774 | 0 | 256 | 0.0188 |

Total: $0.1059. Prices: deepseek line, as measured by its adapter.
