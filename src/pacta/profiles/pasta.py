from __future__ import annotations

from . import Profile


PASTA_PALLAS_PROFILE = Profile(
    kind="pasta_pallas",
    default_certificates=[],
    axiom_imports=["Proofs.FieldMain"],
    guarantees=[
        "Pallas/Pasta arithmetic evidence is treated as foundation work unless aggregate certificates prove otherwise.",
    ],
    preconditions=[
        "Require explicit add, mul, reduce, square, and invert proof coverage before production field claims.",
        "Require an aggregate fieldImplementation-style theorem before classifying the field implementation as complete.",
    ],
    exclusions=[
        "Production-ready Pallas arithmetic is not assumed unless shipped certificates prove it.",
        "Full protocol, wallet, proof-system, or transaction safety is out of scope.",
        "Compiler correctness, translation faithfulness, and side-channel resistance are out of scope.",
    ],
    trusted_base=[
        "Lean kernel and standard library axioms.",
        "Correctness of the shipped translation artifact.",
        "Correct mapping from production code to checked routines.",
    ],
    deployment_constraints=[
        "Do not classify as a complete production field implementation without aggregate field coverage.",
        "Keep downstream protocol use behind independent tests and audits.",
    ],
    invalidation_conditions=[
        "Expected operation certificates are absent or fail replay.",
        "Unexpected axioms appear in certificate audits.",
        "Production code uses routines not covered by the shipped proof artifact.",
    ],
    next_milestones=[
        "Prove add, mul, reduce, square, and invert.",
        "Add an aggregate fieldImplementation-style theorem.",
        "Map the checked theorem boundary to public production APIs.",
    ],
)
