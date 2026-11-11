# Security notes

## Threat model

`agent-manifest-lint` is a pure library plus a thin CLI. It parses and checks a JSON manifest; it does not execute permissions, access the filesystem or network, or enforce anything at runtime.

### Defended

- Invalid JSON, duplicate object keys, a UTF-8 BOM, invalid UTF-8, and a top-level value that is not a JSON object raise `LintError` with code `invalid_json`.
- Input larger than `max_bytes` (default 1,048,576 bytes) raises `LintError` with code `too_large`. The size check runs before parsing.
- JSON nesting deeper than `max_depth` (default 32), including a `RecursionError` from the parser, raises `LintError` with code `too_deep`.
- Manifest-level wildcard permissions (`*` in the value), `fs:read:/`, and `fs:write:/` are reported as `AM002` errors.
- `fs:write` to `/`, `/etc`, `/usr`, `/bin`, `/sbin`, `/boot`, `/sys`, `/proc`, `/root`, anything under those paths, a path with a `..` segment, or a path containing `/.ssh` is reported as an `AM008` error. Raw paths and `posixpath.normpath` results are checked, so `//etc/passwd` and `/./etc/passwd` are caught.
- A tool permission not exactly declared by the manifest is an `AM003` error; a manifest permission not used by any tool is an `AM004` warning; duplicate tool names are `AM005` errors.
- `env` entries containing `=` are rejected with `AM006` and the message `env entry must be a variable name, not a value`; the value is not included in the finding. Other invalid env names are also `AM006`.
- Permission syntax is validated as `fs:read`, `fs:write`, `net`, `shell`, or `env`; invalid syntax is `AM007`. Messages quote at most 64 characters.
- `format_text` removes quote characters from messages before printing.

### Not defended

- Permissions are not enforced. The linter does not sandbox, execute, or restrict an agent at runtime.
- `fs:write` paths outside the restricted list (for example `/tmp`, `/var`, or `/home`) are allowed if they pass syntax checks. Symlinks, mounts, and path resolution on the host are not inspected.
- `net:` hosts are checked only for syntax (`^[a-z0-9.-]+$` or `*`); the linter does not resolve, allowlist, or contact hosts.
- `shell:` commands are checked only for syntax (`^[a-z0-9._-]+$` or `*`); command safety is not evaluated.
- `env:` names are checked only for syntax. The linter does not scan arbitrary strings for secrets outside the `env` entry rule, and it does not detect every possible pasted secret.
- The linter does not validate A2A Agent Cards, MCP tool schemas, or SKILL.md files, and it does not perform general JSON Schema validation.
- The byte and depth limits bound parsing, but the number of permissions inside a document under the byte limit is not separately capped.

## Publishing

This code does not contain publishing credentials. The package has no runtime dependencies. Any release configuration is outside the code described here.
