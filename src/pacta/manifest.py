from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


IMPORT_RE = re.compile(r"^\s*import\s+([A-Za-z0-9_'.]+)", re.MULTILINE)


@dataclass(slots=True)
class VerificationLayout:
    repo_path: Path
    verification_dir: Path
    lean_files: list[Path]
    manifest_files: list[Path] = field(default_factory=list)
    manifest_entries: list[Path] = field(default_factory=list)
    compile_order: list[Path] = field(default_factory=list)
    files_not_in_manifest: list[Path] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def relative_files(self) -> list[str]:
        return [str(path.relative_to(self.verification_dir)) for path in self.lean_files]


def discover_layout(repo_path: str | Path, verification_dir_name: str = "verification") -> VerificationLayout:
    repo = Path(repo_path).resolve()
    verification_dir = repo / verification_dir_name
    lean_files = sorted(verification_dir.rglob("*.lean")) if verification_dir.exists() else []
    manifest_files, manifest_entries = _read_manifest_entries(verification_dir)
    warnings: list[str] = []
    files_not_in_manifest: list[Path] = []
    if manifest_files:
        manifest_set = {path.resolve() for path in manifest_entries if path.exists()}
        files_not_in_manifest = [path for path in lean_files if path.resolve() not in manifest_set]
    if not verification_dir.exists():
        warnings.append(f"Verification directory does not exist: {verification_dir}")
    compile_order, topo_warnings = topological_order(lean_files, verification_dir)
    warnings.extend(topo_warnings)
    return VerificationLayout(
        repo_path=repo,
        verification_dir=verification_dir,
        lean_files=lean_files,
        manifest_files=manifest_files,
        manifest_entries=manifest_entries,
        compile_order=compile_order,
        files_not_in_manifest=files_not_in_manifest,
        warnings=warnings,
    )


def parse_imports(path: str | Path) -> list[str]:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    return IMPORT_RE.findall(text)


def topological_order(files: list[Path], verification_dir: Path) -> tuple[list[Path], list[str]]:
    module_map = _module_aliases(files, verification_dir)
    dependencies: dict[Path, set[Path]] = {path: set() for path in files}
    for path in files:
        for module in parse_imports(path):
            dep = module_map.get(module)
            if dep and dep != path:
                dependencies[path].add(dep)
    ordered: list[Path] = []
    ready = sorted([path for path, deps in dependencies.items() if not deps])
    remaining = {path: set(deps) for path, deps in dependencies.items()}
    while ready:
        path = ready.pop(0)
        if path not in remaining:
            continue
        ordered.append(path)
        del remaining[path]
        for other, deps in list(remaining.items()):
            deps.discard(path)
            if not deps and other not in ready:
                ready.append(other)
        ready.sort()
    if remaining:
        return sorted(files), ["Local Lean import cycle or unresolved topo state; falling back to lexical order."]
    return ordered, []


def _module_aliases(files: list[Path], verification_dir: Path) -> dict[str, Path]:
    aliases: dict[str, Path] = {}
    gen_dir = verification_dir / "gen"
    for path in files:
        for root in (verification_dir, gen_dir):
            try:
                rel = path.relative_to(root)
            except ValueError:
                continue
            module = ".".join(rel.with_suffix("").parts)
            aliases.setdefault(module, path)
    return aliases


def _read_manifest_entries(verification_dir: Path) -> tuple[list[Path], list[Path]]:
    if not verification_dir.exists():
        return [], []
    candidates: list[Path] = []
    for pattern in ("*manifest*", "*proofs*.txt", "*lean-files*.txt", "proofs.txt", "lean_files.txt"):
        candidates.extend(sorted(verification_dir.glob(pattern)))
    candidates = [path for path in dict.fromkeys(candidates) if path.is_file()]
    entries: list[Path] = []
    for manifest in candidates:
        for raw in manifest.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.split("#", 1)[0].split("--", 1)[0].strip().strip('"').strip("'")
            if not line.endswith(".lean"):
                continue
            path = Path(line)
            if not path.is_absolute():
                path = verification_dir / path
            entries.append(path)
    return candidates, entries
