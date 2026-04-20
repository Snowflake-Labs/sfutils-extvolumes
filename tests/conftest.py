"""Shared pytest fixtures for sfutils-extvolumes test suite."""

from __future__ import annotations

import pytest

from sfutils_extvolumes._snow import set_masking, set_snow_cli_options


@pytest.fixture(autouse=True)
def reset_snow_cli_options():
    """Reset global _snow_cli_options state before and after each test.

    _snow.py uses a module-level SnowCLIOptions instance mutated by
    set_masking() and set_snow_cli_options(). Without resetting, state
    set in one test leaks into the next.
    """
    set_snow_cli_options(verbose=False, debug=False, mask_sensitive=True)
    yield
    set_snow_cli_options(verbose=False, debug=False, mask_sensitive=True)
    set_masking(True)
