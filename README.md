# agent-manifest-lint

[![PyPI version](https://img.shields.io/pypi/v/trysac-agent-manifest-lint)](https://pypi.org/project/trysac-agent-manifest-lint/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-agent-manifest-lint)](LICENSE)
[![CI](https://github.com/Trysac/u224-agent-manifest-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u224-agent-manifest-lint/actions/workflows/ci.yml)

Lint agent manifests for least privilege: required fields, wildcard and sensitive permissions, tool permissions not declared, unused grants and inline secrets, with JSON pointers

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-agent-manifest-lint
# or
uv add trysac-agent-manifest-lint
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import agent_manifest_lint

# normalize() trims surrounding whitespace and lower-cases the text.
print(agent_manifest_lint.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    agent_manifest_lint.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
