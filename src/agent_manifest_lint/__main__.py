"""Command-line interface for agent-manifest-lint."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import asdict

from . import LintError, format_text, lint_text


def main(argv: Sequence[str] | None = None) -> int:
    """Run the linter CLI.

    Args:
        argv: Command-line arguments (excluding program name). If ``None``,
            ``sys.argv[1:]`` is used.

    Returns:
        Exit code: 0 on success (no errors), 1 if errors found, 2 on usage,
        I/O, or invalid JSON errors.
    """
    parser = argparse.ArgumentParser(
        prog="agent-manifest-lint",
        description="Lint agent manifests for least privilege.",
    )
    parser.add_argument("path", help="Path to the manifest JSON file")
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        # argparse calls sys.exit on error; convert to return code 2.
        return 2

    try:
        with open(args.path, "rb") as f:
            data = f.read()
    except OSError as exc:
        print(f"Error reading file: {exc}", file=sys.stderr)
        return 2

    try:
        findings = lint_text(data)
    except LintError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        output = json.dumps([asdict(f) for f in findings], sort_keys=True)
        print(output)
    else:
        print(format_text(findings))

    # Return 1 if any error severity, else 0.
    if any(f.severity == "error" for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
