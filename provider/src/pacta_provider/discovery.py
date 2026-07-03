from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from pacta.lean import build_lean_env, detect_tools, resolve_lean_project_dir


SKIP_DIRS = {".git", ".venv", "__pycache__", "node_modules", "target", ".lake", ".pytest_cache"}


@dataclass(slots=True)
class ToolchainCandidate:
    env_script: Path
    lean_project_dir: Path | None
    lean: str | None
    lake: str | None
    aeneas_home: str | None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "env_script": str(self.env_script),
            "lean_project_dir": str(self.lean_project_dir) if self.lean_project_dir else None,
            "lean": self.lean,
            "lake": self.lake,
            "aeneas_home": self.aeneas_home,
        }


def discover_toolchains(roots: Iterable[str | Path] | None = None, max_depth: int = 6) -> list[ToolchainCandidate]:
    home = Path.home()
    search_roots = [home / "GitClone", home] if roots is None else [Path(root).expanduser() for root in roots]
    scripts: list[Path] = []
    for root in search_roots:
        if root.exists():
            scripts.extend(_find_env_scripts(root, max_depth=max_depth))
    candidates: list[ToolchainCandidate] = []
    seen: set[Path] = set()
    for script in scripts:
        if script in seen:
            continue
        seen.add(script)
        env = build_lean_env("verification", env_script=script)
        tools = detect_tools(env)
        project = resolve_lean_project_dir("$AENEAS_HOME/backends/lean", env)
        if project is None:
            project = _nearby_lean_project(script)
        candidates.append(
            ToolchainCandidate(
                env_script=script,
                lean_project_dir=project,
                lean=tools.lean,
                lake=tools.lake,
                aeneas_home=env.get("AENEAS_HOME"),
            )
        )
    return candidates


def _find_env_scripts(root: Path, max_depth: int) -> list[Path]:
    root = root.resolve()
    found: list[Path] = []
    for current, dirs, files in os.walk(root):
        current_path = Path(current)
        rel_depth = len(current_path.relative_to(root).parts)
        if rel_depth >= max_depth:
            dirs[:] = []
        else:
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        if "env.sh" in files and ("aeneas" in str(current_path).lower() or "lean" in str(current_path).lower()):
            found.append(current_path / "env.sh")
    return sorted(found)


def _nearby_lean_project(script: Path) -> Path | None:
    for parent in [script.parent, *script.parents]:
        for candidate in (parent / "aeneas" / "backends" / "lean", parent / "backends" / "lean"):
            if (candidate / "lakefile.lean").exists() or (candidate / "lakefile.toml").exists():
                return candidate
    return None
