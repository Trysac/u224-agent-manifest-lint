"""Behavior tests for the public API of agent_manifest_lint."""

from __future__ import annotations

import pytest

import agent_manifest_lint


def test_normalize_trims_and_lowercases() -> None:
    assert agent_manifest_lint.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        agent_manifest_lint.normalize(value)


def test_version_is_semver() -> None:
    parts = agent_manifest_lint.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
