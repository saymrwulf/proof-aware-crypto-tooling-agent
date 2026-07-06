from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .yamlio import load_data


STANDARD_LEAN_AXIOMS = ["propext", "Classical.choice", "Quot.sound"]


@dataclass(slots=True)
class RepoConfig:
    name: str
    url: str | None = None
    kind: str = "unknown"
    verification_dir: str = "verification"
    verified_backend: str | None = None
    backend_warning: str | None = None
    known_status: str | None = None
    certificates: list[str] = field(default_factory=list)
    expected_axioms: list[str] = field(default_factory=lambda: STANDARD_LEAN_AXIOMS.copy())
    known_exclusions: list[str] = field(default_factory=list)
    axiom_imports: list[str] = field(default_factory=list)
    apex_boundary: str | None = None
    certificate_axioms: dict[str, list[str]] = field(default_factory=dict)
    env_script: str | None = None
    lean_project_dir: str | None = None
    lean_guard: str | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "RepoConfig":
        if "name" not in raw:
            raise ValueError("Repo config is missing required field 'name'")
        return cls(
            name=str(raw["name"]),
            url=raw.get("url"),
            kind=str(raw.get("kind", "unknown")),
            verification_dir=str(raw.get("verification_dir", "verification")),
            verified_backend=raw.get("verified_backend"),
            backend_warning=raw.get("backend_warning"),
            known_status=raw.get("known_status"),
            certificates=list(raw.get("certificates") or []),
            expected_axioms=list(raw.get("expected_axioms") or STANDARD_LEAN_AXIOMS),
            known_exclusions=list(raw.get("known_exclusions") or []),
            axiom_imports=list(raw.get("axiom_imports") or []),
            apex_boundary=raw.get("apex_boundary"),
            certificate_axioms={
                str(name): [str(a) for a in axioms]
                for name, axioms in (raw.get("certificate_axioms") or {}).items()
            },
            env_script=raw.get("env_script"),
            lean_project_dir=raw.get("lean_project_dir"),
            lean_guard=raw.get("lean_guard"),
        )


@dataclass(slots=True)
class AppConfig:
    repos: list[RepoConfig]

    def repo_named(self, name: str) -> RepoConfig:
        for repo in self.repos:
            if repo.name == name:
                return repo
        available = ", ".join(repo.name for repo in self.repos)
        raise KeyError(f"Unknown repo '{name}'. Available: {available}")


def load_config(path: str | Path) -> AppConfig:
    raw = load_data(path)
    if not isinstance(raw, dict) or "repos" not in raw:
        raise ValueError(f"{path} must contain a top-level 'repos' list")
    repos = raw["repos"]
    if not isinstance(repos, list):
        raise ValueError("'repos' must be a list")
    return AppConfig(repos=[RepoConfig.from_dict(item) for item in repos])
