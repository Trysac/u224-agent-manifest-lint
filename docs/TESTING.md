# Testing

## Running

```sh
pytest tests/test_agent_manifest_lint.py
```

## Policy

The test suite is `tests/test_agent_manifest_lint.py`. It uses `pytest` and imports the public API from `agent_manifest_lint` and the CLI `main` from `agent_manifest_lint.__main__`. Tests assert exact findings, messages, pointers, exit codes, and output; there is no coverage threshold or external-service test in this repository.

## Tiers

There is one local test module and no conformance markers or external-tool tests in the provided test file.

## Layout

`tests/test_agent_manifest_lint.py` contains:

- `test_valid_manifest_returns_empty`: a valid manifest returns no findings.
- `test_am002_wildcard_manifest_permission`: a manifest-level `net:*` permission yields `AM002`.
- `test_am003_tool_permission_not_declared`: a tool permission absent from the manifest yields `AM003` at the tool permission pointer.
- `test_am004_unused_manifest_permission`: an unused manifest permission yields `AM004`.
- `test_am006_inline_secret`: `API_TOKEN=abc123` yields `AM006` and the secret value is not present in the finding.
- `test_am008_fs_write_restricted_and_am007_and_missing_name_and_duplicate_tool`: restricted `fs:write` paths yield `AM008`, `disk:read:/x` yields `AM007`, a missing name yields `AM001` at `/name`, and duplicate tool names yield `AM005` at `/tools/1/name`.
- `test_lint_text_errors_and_limits`: invalid JSON and duplicate keys raise `LintError` with `invalid_json`; 1,048,577 bytes raises `too_large` while 1,048,576 bytes is accepted; nesting deeper than 32 raises `too_deep`.
- `test_lint_text_adversarial_nesting_is_too_deep`: deeply nested JSON raises `LintError` with code `too_deep`.
- `test_am002_wildcard_in_shell_and_fs_values`: wildcards in `shell:` and `fs:write:` values yield `AM002`.
- `test_am004_pointer_uses_original_index`: `AM004` points to the original permission index when earlier entries are invalid.
- `test_am008_normalised_paths_are_restricted`: `//etc/passwd` and `/./etc/passwd` yield `AM008`.
- `test_format_text_removes_quotes`: `format_text` removes quote characters from messages.
- `test_pointer_escaping`: pointer components escape `~` as `~0` and `/` as `~1`.
- `test_empty_tools_array_am001`: an empty tools array yields `AM001` at `/tools`.
- `test_permissions_not_strings_am007`: non-string permissions yield `AM007`.
- `test_env_absent_ok`: a manifest without `env` produces no `env` finding.
- `test_am002_root_fs_read_write`: `fs:read:/` and `fs:write:/` yield `AM002`.
- `test_main_text_and_json_output`: CLI text output is one line per finding, JSON output is a sorted-key array, exit code 1 on errors, 0 on warnings/none, 2 on unreadable or invalid files.
