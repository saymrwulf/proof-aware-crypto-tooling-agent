#!/usr/bin/env python3
"""Dependency-free test runner for hosts without pytest.

Discovers tests/test_*.py, runs every test_* function, and supports the
small pytest surface this suite uses: the tmp_path fixture, pytest.raises,
pytest.skip, and pytest.mark.* as no-ops. Prefer real pytest when it is
installed; this shim exists so `python3 scripts/mini_pytest.py` works on a
bare interpreter (the same portability posture as the rest of pacta).
"""
from __future__ import annotations

import importlib.util
import inspect
import sys
import tempfile
import traceback
import types
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for entry in (ROOT / "src", ROOT / "provider" / "src", ROOT):
    sys.path.insert(0, str(entry))


class _Skip(Exception):
    pass


def _install_pytest_stub() -> None:
    if "pytest" in sys.modules:
        return
    stub = types.ModuleType("pytest")

    @contextmanager
    def raises(exc_type, match=None):
        class _Ctx:
            value = None

        ctx = _Ctx()
        try:
            yield ctx
        except exc_type as exc:  # noqa: PERF203
            ctx.value = exc
            if match is not None:
                import re

                if not re.search(match, str(exc)):
                    raise AssertionError(f"exception message {exc!r} does not match {match!r}") from exc
            return
        raise AssertionError(f"expected {exc_type.__name__} was not raised")

    def skip(reason=""):
        raise _Skip(reason)

    class _Mark:
        def __getattr__(self, _name):
            def deco(fn=None, *a, **k):
                return fn if fn is not None else deco

            return deco

    stub.raises = raises
    stub.skip = skip
    stub.mark = _Mark()
    stub.approx = lambda v, **k: v
    sys.modules["pytest"] = stub


class _MonkeyPatch:
    def __init__(self):
        self._attr: list[tuple[object, str, object, bool]] = []
        self._env: list[tuple[str, str | None]] = []

    def setattr(self, target, name, value=None):
        import os

        if value is None and isinstance(target, str):
            # pytest-style dotted target: import the longest importable
            # prefix, then walk attributes (handles module-as-attribute
            # forms like "pkg.module.shutil.which").
            parts = target.split(".")
            obj = None
            for split in range(len(parts) - 1, 0, -1):
                try:
                    obj = importlib.import_module(".".join(parts[:split]))
                except ModuleNotFoundError:
                    continue
                for attr_name in parts[split:-1]:
                    obj = getattr(obj, attr_name)
                break
            if obj is None:
                raise ModuleNotFoundError(target)
            target, name, value = obj, parts[-1], name
        had = hasattr(target, name)
        self._attr.append((target, name, getattr(target, name, None), had))
        setattr(target, name, value)

    def setenv(self, name, value):
        import os

        self._env.append((name, os.environ.get(name)))
        os.environ[name] = value

    def delenv(self, name, raising=True):
        import os

        self._env.append((name, os.environ.get(name)))
        os.environ.pop(name, None if not raising else os.environ[name] and None)

    def undo(self):
        import os

        for target, name, old, had in reversed(self._attr):
            if had:
                setattr(target, name, old)
            else:
                delattr(target, name)
        for name, old in reversed(self._env):
            if old is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = old


class _CapSys:
    def __init__(self):
        import io

        self._out, self._err = io.StringIO(), io.StringIO()
        self._old = (sys.stdout, sys.stderr)
        sys.stdout, sys.stderr = self._out, self._err

    def readouterr(self):
        out, err = self._out.getvalue(), self._err.getvalue()
        self._out.truncate(0), self._out.seek(0)
        self._err.truncate(0), self._err.seek(0)
        return types.SimpleNamespace(out=out, err=err)

    def stop(self):
        sys.stdout, sys.stderr = self._old


def _load(path: Path) -> types.ModuleType:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def main(argv: list[str]) -> int:
    _install_pytest_stub()
    pattern = argv[1] if len(argv) > 1 else ""
    passed = failed = skipped = 0
    failures: list[str] = []
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        if pattern and pattern not in path.name:
            continue
        try:
            module = _load(path)
        except Exception:
            failed += 1
            failures.append(f"{path.name}: import error\n{traceback.format_exc()}")
            continue
        for name in sorted(dir(module)):
            if not name.startswith("test_"):
                continue
            fn = getattr(module, name)
            if not callable(fn):
                continue
            kwargs = {}
            params = inspect.signature(fn).parameters
            tmp = None
            cleanups = []
            if "tmp_path" in params:
                tmp = tempfile.TemporaryDirectory(prefix="mini-pytest-")
                kwargs["tmp_path"] = Path(tmp.name)
            if "monkeypatch" in params:
                mp = _MonkeyPatch()
                kwargs["monkeypatch"] = mp
                cleanups.append(mp.undo)
            if "capsys" in params:
                cap = _CapSys()
                kwargs["capsys"] = cap
                cleanups.append(cap.stop)
            unknown = [p for p in params if p not in kwargs]
            if unknown:
                skipped += 1
                print(f"s {path.name}::{name} (unsupported fixtures: {unknown})")
                continue
            try:
                fn(**kwargs)
                passed += 1
                print(f". {path.name}::{name}")
            except _Skip as exc:
                skipped += 1
                print(f"s {path.name}::{name} ({exc})")
            except Exception:
                failed += 1
                failures.append(f"{path.name}::{name}\n{traceback.format_exc()}")
                print(f"F {path.name}::{name}")
            finally:
                for cleanup in cleanups:
                    cleanup()
                if tmp is not None:
                    tmp.cleanup()
    print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
    for failure in failures:
        print("\n" + "=" * 70)
        print(failure)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
