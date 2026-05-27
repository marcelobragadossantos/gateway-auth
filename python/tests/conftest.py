"""Pytest configuration / shared fixtures.

Enables asyncio for the FastAPI middleware tests without forcing a hard
dependency on pytest-asyncio (some users may rely on the bundled anyio
plugin instead). We register a minimal asyncio runner via a fixture.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest


def pytest_collection_modifyitems(config, items):
    """Auto-mark async test functions so we can run them without pytest-asyncio."""
    for item in items:
        if inspect.iscoroutinefunction(getattr(item, "function", None)):
            item.add_marker(pytest.mark.asyncio)


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem):
    """Run async test functions in a fresh event loop."""
    func = pyfuncitem.obj
    if not inspect.iscoroutinefunction(func):
        return None
    funcargs = pyfuncitem.funcargs
    sig = inspect.signature(func)
    kwargs = {name: funcargs[name] for name in sig.parameters if name in funcargs}
    asyncio.run(func(**kwargs))
    return True
