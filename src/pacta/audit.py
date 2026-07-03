from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .manifest import VerificationLayout


@dataclass(slots=True)
class HygieneIssue:
    severity: str
    code: str
    path: str
    line: int
    message: str

    def to_dict(self) -> dict[str, object]:
        return {
            "severity": self.severity,
            "code": self.code,
            "path": self.path,
            "line": self.line,
            "message": self.message,
        }


SORRY_RE = re.compile(r"\bsorry\b")
AXIOM_RE = re.compile(r"^\s*axiom\s+[A-Za-z0-9_'.]+", re.MULTILINE)
TRUE_TARGET_RE = re.compile(r"\b(?:theorem|lemma)\s+[A-Za-z0-9_'.]+[\s\S]{0,240}?:\s*True\s*:=")
BY_TRIVIAL_RE = re.compile(r"\bby\s+trivial\b")
NATIVE_DECIDE_RE = re.compile(r"\bnative_decide\b")


def scan_hygiene(layout: VerificationLayout, certificates: list[str] | None = None) -> list[HygieneIssue]:
    issues: list[HygieneIssue] = []
    certs = certificates or []
    seen_text = ""
    for path in layout.lean_files:
        rel = _rel(path, layout.verification_dir)
        text = path.read_text(encoding="utf-8", errors="ignore")
        code = strip_lean_comments(text)
        seen_text += "\n" + code
        issues.extend(_scan_file(path, rel, code))
    for path in layout.files_not_in_manifest:
        issues.append(
            HygieneIssue(
                severity="warning",
                code="proof-file-not-in-manifest",
                path=_rel(path, layout.verification_dir),
                line=1,
                message="Lean proof file is not listed in an explicit manifest.",
            )
        )
    for cert in certs:
        if cert and cert not in seen_text:
            issues.append(
                HygieneIssue(
                    severity="error",
                    code="missing-certificate-name",
                    path=str(layout.verification_dir),
                    line=1,
                    message=f"Configured certificate name was not found in scanned Lean files: {cert}",
                )
            )
    return issues


def strip_lean_comments(text: str) -> str:
    out: list[str] = []
    i = 0
    depth = 0
    while i < len(text):
        if depth == 0 and text.startswith("--", i):
            while i < len(text) and text[i] != "\n":
                i += 1
            if i < len(text):
                out.append("\n")
                i += 1
            continue
        if text.startswith("/-", i):
            depth += 1
            i += 2
            continue
        if depth > 0:
            if text.startswith("-/", i):
                depth -= 1
                i += 2
            else:
                if text[i] == "\n":
                    out.append("\n")
                i += 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def _scan_file(path: Path, rel: str, code: str) -> list[HygieneIssue]:
    issues: list[HygieneIssue] = []
    for match in SORRY_RE.finditer(code):
        issues.append(_issue("error", "sorry", rel, code, match.start(), "Executable Lean code contains 'sorry'."))
    if _is_under_proofs(path) and AXIOM_RE.search(code):
        for match in AXIOM_RE.finditer(code):
            issues.append(_issue("error", "axiom-in-proofs", rel, code, match.start(), "Proofs/ contains an axiom declaration."))
    for match in TRUE_TARGET_RE.finditer(code):
        issues.append(_issue("warning", "trivial-true-target", rel, code, match.start(), "Theorem or lemma target appears to be trivially True."))
    if _is_spec_or_certificate(path):
        for match in BY_TRIVIAL_RE.finditer(code):
            issues.append(_issue("warning", "by-trivial-in-spec", rel, code, match.start(), "Spec/certificate/root file contains 'by trivial'."))
    for match in NATIVE_DECIDE_RE.finditer(code):
        issues.append(_issue("advisory", "native-decide", rel, code, match.start(), "native_decide appears in proof code; review dependency cone."))
    return issues


def _issue(severity: str, code_name: str, rel: str, code: str, offset: int, message: str) -> HygieneIssue:
    return HygieneIssue(severity=severity, code=code_name, path=rel, line=code.count("\n", 0, offset) + 1, message=message)


def _is_under_proofs(path: Path) -> bool:
    return "Proofs" in path.parts


def _is_spec_or_certificate(path: Path) -> bool:
    lower = path.name.lower()
    return any(token in lower for token in ("spec", "certificate", "main", "root"))


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
