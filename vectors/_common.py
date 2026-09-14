"""Shared helpers for vector modules (not itself a vector: `_` prefix)."""
import os

try:  # loaded by the runner as a top-level module
    import base as _base
except ImportError:  # pragma: no cover - loaded as sandeval.base
    from sandeval import base as _base


def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(_base.__file__)))


def tools_dir() -> str:
    return os.path.join(repo_root(), "tools")


def marker(name: str) -> str:
    return f"SANDEVAL_POC_{name}"


def safe_name(path: str) -> str:
    return path.replace("/", "_").lstrip("_")
