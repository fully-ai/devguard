"""Plugin loader for custom Python rule modules."""

from __future__ import annotations

import importlib.util
from collections.abc import Callable
from pathlib import Path

from devguard.models import Finding, GuardConfig

PluginFn = Callable[[Path, GuardConfig], list[Finding]]


def load_plugins(plugin_paths: list[Path]) -> list[PluginFn]:
    callables: list[PluginFn] = []
    for path in plugin_paths:
        if not path.is_file() or path.suffix != ".py":
            continue
        spec = importlib.util.spec_from_file_location(f"devguard_plugin_{path.stem}", path)
        if spec is None or spec.loader is None:
            continue
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        fn = getattr(mod, "run_plugin", None)
        if callable(fn):
            callables.append(fn)
    return callables
