from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .config import RepoConfig


@dataclass(slots=True)
class RepoStatus:
    name: str
    url: str | None
    local_path: Path
    exists: bool
    verification_dir: Path
    verification_exists: bool
    commit: str | None


def configured_local_path(repo: RepoConfig, base_dir: str | Path = "repos") -> Path:
    return Path(base_dir) / repo.name


def status_for(repo: RepoConfig, base_dir: str | Path = "repos", explicit_path: str | Path | None = None) -> RepoStatus:
    local_path = Path(explicit_path) if explicit_path else configured_local_path(repo, base_dir)
    verification_dir = local_path / repo.verification_dir
    return RepoStatus(
        name=repo.name,
        url=repo.url,
        local_path=local_path,
        exists=local_path.exists(),
        verification_dir=verification_dir,
        verification_exists=verification_dir.exists(),
        commit=git_commit(local_path) if local_path.exists() else None,
    )


def git_commit(path: str | Path) -> str | None:
    git = shutil.which("git")
    if not git:
        return None
    try:
        completed = subprocess.run(
            [git, "-C", str(path), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def clone_or_fetch(repo: RepoConfig, base_dir: str | Path = "repos", fetch: bool = False) -> RepoStatus:
    if not repo.url:
        raise ValueError(f"{repo.name} has no URL")
    git = shutil.which("git")
    if not git:
        raise RuntimeError("git is not available")
    local_path = configured_local_path(repo, base_dir)
    local_path.parent.mkdir(parents=True, exist_ok=True)
    if local_path.exists():
        if fetch:
            subprocess.run([git, "-C", str(local_path), "fetch", "--all", "--prune"], check=True, timeout=120)
    else:
        subprocess.run([git, "clone", repo.url, str(local_path)], check=True, timeout=300)
    return status_for(repo, base_dir)
