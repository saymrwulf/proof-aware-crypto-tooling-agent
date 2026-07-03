from __future__ import annotations

from . import Profile


ED25519_PROFILE = Profile(
    kind="ed25519",
    default_certificates=[
        "CurveFieldProofs.fieldImplementation",
        "CurveFieldProofs.edwardsImplementation",
    ],
    axiom_imports=[
        "Proofs.FieldMain",
        "Proofs.EdMain",
    ],
    guarantees=[
        "FieldElement51 arithmetic is checked through denotation over F_p, p = 2^255 - 19, for the configured backend.",
        "Selected complete twisted Edwards point-operation laws are checked under ExtValid and OnCurveExt invariants.",
        "Panic and overflow freedom evidence applies under the stated limb-bound preconditions.",
        "Implementation laws are interpreted through the shipped Lean denotation layer.",
    ],
    preconditions=[
        "Use the exact pinned source or a reviewed diff against the checked artifact.",
        "Use the configured serial/u64 backend unless another backend has its own certificate.",
        "Maintain limb bounds and representation invariants required by the Lean statements.",
        "Treat Charon/Aeneas translation faithfulness as trusted base, not as proven by this tool.",
    ],
    exclusions=[
        "Full EdDSA signature verification is not proven by field/Edwards certificates alone.",
        "Complete Scalar52 arithmetic is out of scope unless separately certified.",
        "SHA-512 is out of scope.",
        "Encoding, decoding, and canonicality are out of scope unless separately certified.",
        "Rust compiler correctness is out of scope.",
        "Charon/Aeneas translation faithfulness is out of scope.",
        "Side-channel resistance is out of scope.",
        "SIMD, AVX, hardware, zkVM, accelerator, and syscall paths are out of scope unless separately certified.",
        "Wallet policy, transaction construction, RPC, oracle, market, and LLM decision safety are out of scope.",
    ],
    trusted_base=[
        "Lean kernel and standard library axioms.",
        "Lake/Lean package resolution used for replay.",
        "Correctness of the shipped Rust-to-Lean translation artifact.",
        "Correct mapping from the production code path to the checked backend.",
        "Operating system, filesystem, and subprocess execution environment.",
    ],
    deployment_constraints=[
        "Use exact pinned source or reviewed diff.",
        "Use verified serial/u64 backend only.",
        "Disable accelerator, syscall, hardware, SIMD, and AVX paths unless separately certified.",
        "Do not treat this as full EdDSA verification.",
        "Keep key custody behind HSM, MPC, or policy firewall until signing-stack proof coverage improves.",
        "Use ordinary tests and fuzzing at encoding, API, and transaction boundaries.",
    ],
    invalidation_conditions=[
        "The deployed code path differs from the checked backend or source revision.",
        "A certificate stops compiling under the pinned Lean environment.",
        "Unexpected axioms appear in certificate audits.",
        "Required invariants are not enforced before calling verified routines.",
        "The implementation uses accelerator or syscall paths not covered by the certificates.",
    ],
    next_milestones=[
        "Prove complete scalar arithmetic.",
        "Prove encoding, decoding, canonicality, and rejection rules.",
        "Connect field, scalar, hash, and point proofs into an EdDSA verification theorem.",
        "Document a reproducible production build and code-path selection story.",
        "Add side-channel and backend-specific assurance evidence.",
    ],
)
