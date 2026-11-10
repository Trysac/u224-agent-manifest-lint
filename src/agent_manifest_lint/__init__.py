"""Lint agent manifests for least privilege.

This module provides a linter for a documented manifest format that checks
for required fields, wildcard permissions, sensitive file system writes,
undeclared tool permissions, unused grants, and inline secrets.
"""

from __future__ import annotations

import json
import logging
import posixpath
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, TypeAlias

__all__ = ["Finding", "LintError", "__version__", "format_text", "lint", "lint_text"]

__version__ = "0.1.0"

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class LintError(Exception):
    """Raised when the input document cannot be parsed or exceeds limits."""

    def __init__(
        self,
        code: Literal["invalid_json", "too_large", "too_deep"],
        message: str = "",
    ) -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


Severity: TypeAlias = Literal["error", "warning"]


@dataclass(frozen=True)
class Finding:
    """A single lint finding."""

    rule: str
    severity: Severity
    pointer: str
    message: str


# ---------------------------------------------------------------------------
# Regular expressions and constants
# ---------------------------------------------------------------------------

NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
# Semantic Versioning 2.0.0 suggested regex (https://semver.org/#is-there-a-suggested-regular-expression-for-checking-a-semver-string)
SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)
ENV_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
SHELL_CMD_RE = re.compile(r"^[a-z0-9._-]+$|^\*$")
NET_HOST_RE = re.compile(r"^[a-z0-9.-]+$|^\*$")  # lowercase host or '*'
FS_READ_PREFIX = "fs:read:"
FS_WRITE_PREFIX = "fs:write:"
NET_PREFIX = "net:"
SHELL_PREFIX = "shell:"
ENV_PREFIX = "env:"

RESTRICTED_WRITE_PATHS = (
    "/",
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/boot",
    "/sys",
    "/proc",
    "/root",
)

MAX_DESCRIPTION_LEN = 1024
MIN_TOOL_DESC_LEN = 10
MAX_PATH_FOR_MSG = 64


def _escape_pointer_component(part: str) -> str:
    """Escape a JSON Pointer component per RFC 6901."""
    return part.replace("~", "~0").replace("/", "~1")


def _build_pointer(parts: Sequence[str | int]) -> str:
    """Build a JSON Pointer from path parts."""
    escaped = [
        _escape_pointer_component(str(part)) if isinstance(part, str) else str(part)
        for part in parts
    ]
    return "/" + "/".join(escaped)


def _pointer_sort_key(pointer: str) -> tuple[Any, ...]:
    """Return a sortable tuple for a JSON Pointer, numeric segments as ints."""
    if pointer == "":
        return ()
    parts = pointer.split("/")[1:]  # drop leading empty
    key: list[Any] = []
    for part in parts:
        unescaped = part.replace("~1", "/").replace("~0", "~")
        if unescaped.isdigit():
            key.append(int(unescaped))
        else:
            key.append(unescaped)
    return tuple(key)


def _truncate_for_msg(s: str, max_len: int = MAX_PATH_FOR_MSG) -> str:
    """Truncate a string for quoting in error messages."""
    if len(s) <= max_len:
        return s
    return s[:max_len] + "..."


def _remove_quotes(s: str) -> str:
    """Remove all quote characters from a message."""
    return s.replace('"', "").replace("'", "")


def _parse_permission(perm: str) -> tuple[str, str]:
    """Parse a permission string, returning (kind, value).

    Raises ValueError if the syntax is invalid.
    """
    if not isinstance(perm, str):
        raise ValueError(f"permission must be a string, got {type(perm).__name__}")
    if perm.startswith(FS_READ_PREFIX):
        path = perm[len(FS_READ_PREFIX) :]
        if not path.startswith("/"):
            raise ValueError(f"invalid fs:read path: '{_truncate_for_msg(perm)}'")
        return ("fs:read", path)
    if perm.startswith(FS_WRITE_PREFIX):
        path = perm[len(FS_WRITE_PREFIX) :]
        if not path.startswith("/"):
            raise ValueError(f"invalid fs:write path: '{_truncate_for_msg(perm)}'")
        return ("fs:write", path)
    if perm.startswith(NET_PREFIX):
        host = perm[len(NET_PREFIX) :]
        if not NET_HOST_RE.fullmatch(host):
            raise ValueError(f"invalid net host: '{_truncate_for_msg(perm)}'")
        return ("net", host)
    if perm.startswith(SHELL_PREFIX):
        cmd = perm[len(SHELL_PREFIX) :]
        if not SHELL_CMD_RE.fullmatch(cmd):
            raise ValueError(f"invalid shell command: '{_truncate_for_msg(perm)}'")
        return ("shell", cmd)
    if perm.startswith(ENV_PREFIX):
        name = perm[len(ENV_PREFIX) :]
        if not ENV_NAME_RE.fullmatch(name):
            raise ValueError(f"invalid env name: '{_truncate_for_msg(perm)}'")
        return ("env", name)
    raise ValueError(f"unknown permission type: '{_truncate_for_msg(perm)}'")


def _is_restricted_write_path(path: str) -> bool:
    """Return True if a fs:write path is restricted.

    The raw path is checked for traversal segments first, then the path is
    normalised so that equivalent spellings such as ``//etc/passwd`` or
    ``/./etc/passwd`` cannot bypass the restricted-prefix check.
    """
    if any(segment == ".." for segment in path.split("/")):
        return True
    if "/.ssh" in path:
        return True
    normalised = posixpath.normpath(path)
    # POSIX keeps exactly two leading slashes; collapse them for comparison.
    while normalised.startswith("//"):
        normalised = normalised[1:]
    if normalised == "/":
        return True
    if "/.ssh" in normalised:
        return True
    return any(
        normalised == restricted or normalised.startswith(restricted + "/")
        for restricted in RESTRICTED_WRITE_PATHS
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """object_pairs_hook to reject duplicate JSON object keys."""
    d: dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key: {k}")
        d[k] = v
    return d


def _json_depth(obj: Any) -> int:
    """Compute maximum nesting depth of a parsed JSON object iteratively."""
    max_depth = 0
    stack: list[tuple[Any, int]] = [(obj, 0)]
    while stack:
        current, depth = stack.pop()
        if isinstance(current, list):
            depth += 1
            if depth > max_depth:
                max_depth = depth
            for item in current:
                stack.append((item, depth))
        elif isinstance(current, dict):
            depth += 1
            if depth > max_depth:
                max_depth = depth
            for value in current.values():
                stack.append((value, depth))
    return max_depth


def _raw_max_depth(text: str) -> int:
    """Compute maximum bracket nesting depth of raw JSON text.

    This runs before parsing so that adversarially nested documents are
    rejected as ``too_deep`` even when the parser would fail with a
    ``JSONDecodeError`` (or ``RecursionError``) first. Brackets inside
    strings are ignored.
    """
    depth = 0
    max_depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > max_depth:
                max_depth = depth
        elif ch in "]}" and depth > 0:
            depth -= 1
    return max_depth


def lint(manifest: Mapping[str, Any]) -> list[Finding]:
    """Lint a manifest mapping and return findings.

    Args:
        manifest: A mapping representing the parsed manifest.

    Returns:
        A list of :class:`Finding` objects, sorted by pointer (document order)
        then rule.
    """
    findings: list[Finding] = []

    # Helper to add a finding.
    def add(
        rule: str, severity: Severity, pointer_parts: Sequence[str | int], message: str
    ) -> None:
        findings.append(Finding(rule, severity, _build_pointer(pointer_parts), message))

    # Validate required fields and collect valid permissions/tools.
    manifest_permissions: list[tuple[str, str]] = []  # (kind, value) for later checks
    manifest_permission_strings: list[str] = []
    valid_permissions: list[tuple[int, str]] = []  # (original index, string)
    tools_data: list[dict[str, Any]] = []
    used_permission_strings: set[str] = set()

    # name
    if "name" not in manifest:
        add("AM001", "error", ["name"], "missing required field name")
    else:
        name = manifest["name"]
        if not isinstance(name, str) or not NAME_RE.fullmatch(name) or not (1 <= len(name) <= 64):
            add("AM001", "error", ["name"], "invalid field name")

    # version
    if "version" not in manifest:
        add("AM001", "error", ["version"], "missing required field version")
    else:
        version = manifest["version"]
        if not isinstance(version, str) or not SEMVER_RE.fullmatch(version):
            add("AM001", "error", ["version"], "invalid field version")

    # description
    if "description" not in manifest:
        add("AM001", "error", ["description"], "missing required field description")
    else:
        desc = manifest["description"]
        if not isinstance(desc, str) or not (1 <= len(desc) <= MAX_DESCRIPTION_LEN):
            add("AM001", "error", ["description"], "invalid field description")

    # permissions
    if "permissions" not in manifest:
        add("AM001", "error", ["permissions"], "missing required field permissions")
    else:
        perms = manifest["permissions"]
        if not isinstance(perms, list):
            add("AM001", "error", ["permissions"], "invalid field permissions")
        else:
            for idx, p in enumerate(perms):
                if not isinstance(p, str):
                    add(
                        "AM007",
                        "error",
                        ["permissions", idx],
                        f"invalid permission syntax: '{_truncate_for_msg(str(p))}'",
                    )
                    continue
                try:
                    kind, value = _parse_permission(p)
                except ValueError:
                    add(
                        "AM007",
                        "error",
                        ["permissions", idx],
                        f"invalid permission syntax: '{_truncate_for_msg(str(p))}'",
                    )
                    continue
                manifest_permissions.append((kind, value))
                manifest_permission_strings.append(p)
                valid_permissions.append((idx, p))
                # AM002: wildcard value or root fs:read/write at manifest level
                if "*" in value:
                    add("AM002", "error", ["permissions", idx], f"wildcard permission '{p}'")
                elif kind == "fs:read" and value == "/":
                    add("AM002", "error", ["permissions", idx], f"root fs:read permission '{p}'")
                elif kind == "fs:write" and value == "/":
                    add("AM002", "error", ["permissions", idx], f"root fs:write permission '{p}'")
                # AM008 for fs:write restricted
                if kind == "fs:write" and _is_restricted_write_path(value):
                    add(
                        "AM008",
                        "error",
                        ["permissions", idx],
                        f"fs:write to restricted path '{_truncate_for_msg(value)}'",
                    )

    # tools
    if "tools" not in manifest:
        add("AM001", "error", ["tools"], "missing required field tools")
    else:
        tools = manifest["tools"]
        if not isinstance(tools, list):
            add("AM001", "error", ["tools"], "invalid field tools")
        elif len(tools) == 0:
            # Edge case: empty tools array is invalid (spec says tools array of 1-128)
            add("AM001", "error", ["tools"], "tools array must not be empty")
        elif len(tools) > 128:
            add("AM001", "error", ["tools"], "tools array must not exceed 128 entries")
        else:
            # First pass: collect tool objects and validate names, descriptions later
            tool_names: list[str] = []
            for idx, tool in enumerate(tools):
                if not isinstance(tool, Mapping):
                    add("AM001", "error", ["tools", idx], "invalid tool object")
                    tools_data.append({})
                    tool_names.append("")
                    continue
                tool_dict = dict(tool)
                tools_data.append(tool_dict)
                # name
                if "name" not in tool_dict:
                    add("AM001", "error", ["tools", idx, "name"], "missing required field name")
                    tool_names.append("")
                else:
                    tname = tool_dict["name"]
                    if not isinstance(tname, str) or not re.fullmatch(
                        r"^[a-z][a-z0-9_]{0,63}$", tname
                    ):
                        add("AM001", "error", ["tools", idx, "name"], "invalid field name")
                        tool_names.append(tname if isinstance(tname, str) else "")
                    else:
                        tool_names.append(tname)
                # description
                if "description" not in tool_dict:
                    add(
                        "AM001",
                        "error",
                        ["tools", idx, "description"],
                        "missing required field description",
                    )
                else:
                    tdesc = tool_dict["description"]
                    if not isinstance(tdesc, str):
                        add(
                            "AM001",
                            "error",
                            ["tools", idx, "description"],
                            "invalid field description",
                        )
                    elif len(tdesc) < MIN_TOOL_DESC_LEN:
                        add(
                            "AM009",
                            "warning",
                            ["tools", idx, "description"],
                            "tool description is shorter than 10 characters",
                        )
                # permissions
                if "permissions" not in tool_dict:
                    add(
                        "AM001",
                        "error",
                        ["tools", idx, "permissions"],
                        "missing required field permissions",
                    )
                else:
                    tperms = tool_dict["permissions"]
                    if not isinstance(tperms, list):
                        add(
                            "AM001",
                            "error",
                            ["tools", idx, "permissions"],
                            "invalid field permissions",
                        )

            # AM005: duplicate tool names (later occurrence flagging)
            seen: dict[str, int] = {}
            for idx, tname in enumerate(tool_names):
                if not tname:
                    continue
                if tname in seen:
                    add(
                        "AM005",
                        "error",
                        ["tools", idx, "name"],
                        "duplicate tool name",
                    )
                else:
                    seen[tname] = idx

            # Second pass: validate tool permissions and perform relation checks (AM003)
            for idx, tool_dict in enumerate(tools_data):
                if "permissions" in tool_dict and isinstance(tool_dict["permissions"], list):
                    for pidx, p in enumerate(tool_dict["permissions"]):
                        if not isinstance(p, str):
                            add(
                                "AM007",
                                "error",
                                ["tools", idx, "permissions", pidx],
                                f"invalid permission syntax: '{_truncate_for_msg(str(p))}'",
                            )
                            continue
                        try:
                            kind, value = _parse_permission(p)
                        except ValueError:
                            add(
                                "AM007",
                                "error",
                                ["tools", idx, "permissions", pidx],
                                f"invalid permission syntax: '{_truncate_for_msg(str(p))}'",
                            )
                            continue
                        used_permission_strings.add(p)
                        # AM008 for fs:write restricted (applies to tool permissions too)
                        if kind == "fs:write" and _is_restricted_write_path(value):
                            add(
                                "AM008",
                                "error",
                                ["tools", idx, "permissions", pidx],
                                f"fs:write to restricted path '{_truncate_for_msg(value)}'",
                            )
                        # AM003: tool permission not declared by manifest
                        if p not in manifest_permission_strings:
                            add(
                                "AM003",
                                "error",
                                ["tools", idx, "permissions", pidx],
                                f"tool permission '{p}' is not declared by the agent",
                            )

    # env (optional)
    if "env" in manifest:
        env = manifest["env"]
        if not isinstance(env, list):
            add("AM001", "error", ["env"], "invalid field env")
        else:
            for idx, entry in enumerate(env):
                if not isinstance(entry, str):
                    add("AM006", "error", ["env", idx], "invalid env variable name")
                    continue
                if "=" in entry:
                    add(
                        "AM006",
                        "error",
                        ["env", idx],
                        "env entry must be a variable name, not a value",
                    )
                elif not ENV_NAME_RE.fullmatch(entry):
                    add("AM006", "error", ["env", idx], "invalid env variable name")

    # AM004: unused manifest-level permissions
    used_set = set(used_permission_strings)
    for idx, p in valid_permissions:
        if p not in used_set:
            add(
                "AM004",
                "warning",
                ["permissions", idx],
                f"permission '{p}' is not used by any tool",
            )

    # Sort findings by pointer (document order) then rule.
    findings.sort(key=lambda f: (_pointer_sort_key(f.pointer), f.rule))
    return findings


def lint_text(
    text: str | bytes,
    *,
    max_bytes: int = 1_048_576,
    max_depth: int = 32,
) -> list[Finding]:
    """Parse and lint a manifest given as UTF-8 text or bytes.

    Args:
        text: The manifest document as ``str`` or ``bytes``.
        max_bytes: Maximum allowed size in bytes (default 1 MiB).
        max_depth: Maximum allowed JSON nesting depth (default 32).

    Returns:
        A list of :class:`Finding` objects.

    Raises:
        LintError: If the document is invalid, too large, or too deeply nested.
    """
    # Determine byte size.
    data = text.encode("utf-8") if isinstance(text, str) else text
    if len(data) > max_bytes:
        raise LintError(
            "too_large",
            f"JSON document exceeds {max_bytes} bytes",
        )
    # Reject BOM.
    if data.startswith(b"\xef\xbb\xbf"):
        raise LintError("invalid_json", "BOM not allowed")
    # Decode UTF-8.
    try:
        text_str = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LintError("invalid_json", "invalid UTF-8") from exc
    # Reject deeply nested documents before parsing: the parser may report a
    # JSONDecodeError or exhaust the interpreter's recursion limit first, and
    # either way the correct classification here is "too_deep".
    if _raw_max_depth(text_str) > max_depth:
        raise LintError(
            "too_deep",
            f"JSON nesting exceeds {max_depth} levels",
        )
    # Parse JSON with duplicate-key rejection. A deeply nested document can
    # exhaust the interpreter's recursion limit inside the parser before the
    # depth check below runs, so treat that as "too_deep".
    try:
        parsed = json.loads(text_str, object_pairs_hook=_reject_duplicate_keys)
    except RecursionError as exc:
        raise LintError(
            "too_deep",
            f"JSON nesting exceeds {max_depth} levels",
        ) from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise LintError("invalid_json", str(exc)) from exc
    # Check depth.
    depth = _json_depth(parsed)
    if depth > max_depth:
        raise LintError(
            "too_deep",
            f"JSON nesting exceeds {max_depth} levels",
        )
    # Ensure top-level is an object.
    if not isinstance(parsed, dict):
        raise LintError("invalid_json", "manifest must be a JSON object")
    return lint(parsed)


def format_text(findings: Sequence[Finding]) -> str:
    """Format findings as one line per finding.

    Line format: ``<rule> <severity> <pointer> <message>`` with quote marks
    removed from the message.
    """
    lines = [f"{f.rule} {f.severity} {f.pointer} {_remove_quotes(f.message)}" for f in findings]
    return "\n".join(lines)
