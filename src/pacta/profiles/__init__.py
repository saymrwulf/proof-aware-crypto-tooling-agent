from __future__ import annotations

from dataclasses import dataclass, field

from pacta.config import RepoConfig, STANDARD_LEAN_AXIOMS


@dataclass(slots=True)
class Profile:
    kind: str
    default_certificates: list[str] = field(default_factory=list)
    axiom_imports: list[str] = field(default_factory=list)
    guarantees: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    trusted_base: list[str] = field(default_factory=list)
    deployment_constraints: list[str] = field(default_factory=list)
    invalidation_conditions: list[str] = field(default_factory=list)
    next_milestones: list[str] = field(default_factory=list)
    expected_axioms: list[str] = field(default_factory=lambda: STANDARD_LEAN_AXIOMS.copy())
    certificate_axioms: dict[str, list[str]] = field(default_factory=dict)
    r4_requirements: list[str] = field(default_factory=list)

    def expected_axioms_for(self, certificate: str) -> list[str]:
        return list(self.certificate_axioms.get(certificate, self.expected_axioms))

    def merge_repo(self, repo: RepoConfig) -> "Profile":
        certs = repo.certificates or self.default_certificates
        imports = repo.axiom_imports or self.axiom_imports
        certificate_axioms = dict(self.certificate_axioms)
        if repo.apex_boundary:
            from .ed25519 import certificate_axioms_for_boundary

            certificate_axioms.update(certificate_axioms_for_boundary(repo.apex_boundary))
        certificate_axioms.update(repo.certificate_axioms)
        exclusions = [*self.exclusions, *repo.known_exclusions]
        constraints = list(self.deployment_constraints)
        if repo.backend_warning:
            constraints.append(repo.backend_warning)
        if repo.known_status:
            constraints.append(repo.known_status)
        return Profile(
            kind=self.kind,
            default_certificates=certs,
            axiom_imports=imports,
            guarantees=list(self.guarantees),
            preconditions=list(self.preconditions),
            exclusions=_dedupe(exclusions),
            trusted_base=list(self.trusted_base),
            deployment_constraints=_dedupe(constraints),
            invalidation_conditions=list(self.invalidation_conditions),
            next_milestones=list(self.next_milestones),
            expected_axioms=repo.expected_axioms or self.expected_axioms,
            certificate_axioms=certificate_axioms,
            r4_requirements=list(self.r4_requirements),
        )


def get_profile(kind: str, repo: RepoConfig | None = None) -> Profile:
    from .ed25519 import ED25519_PROFILE
    from .pasta import PASTA_PALLAS_PROFILE

    profiles = {
        "ed25519": ED25519_PROFILE,
        "pasta_pallas": PASTA_PALLAS_PROFILE,
    }
    profile = profiles.get(kind, Profile(kind=kind))
    return profile.merge_repo(repo) if repo else profile


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out
