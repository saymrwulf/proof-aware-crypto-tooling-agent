from __future__ import annotations

from pacta.config import STANDARD_LEAN_AXIOMS

from . import Profile

# Per-fork signature-apex boundary axiom sets.
#
# AUTHORITY: each verified repo's check.sh Phase 3b is the enforcement point;
# these lists mirror what those buttons pin, certificate by certificate. If a
# repo's button and this table ever disagree, the button wins and this table
# is stale. The boundary axioms are the DOCUMENTED trusted base of the apex
# tiers (the SHA-512 oracle and opaque wire-format items) - they are not
# accidents, and a cone that deviates from its boundary in EITHER direction
# (extra axioms or missing ones) must be treated as dirty.
APEX_BOUNDARIES: dict[str, list[str]] = {
    # upstream dalek, sha2-0.11 three-wrapper oracle
    "dalek-wrappers": [
        *STANDARD_LEAN_AXIOMS,
        "ed25519.Signature",
        "sha2.Sha512",
        "verifying.sha512_new",
        "verifying.sha512_update",
        "verifying.sha512_finalize_bytes",
        "ed25519.Signature.to_bytes",
        "signature.error.Error",
        "signature.error.Error.new",
    ],
    # risc0 / betrusted, sha2-0.10 single-call sha512_hash3 oracle
    "hash3": [
        *STANDARD_LEAN_AXIOMS,
        "ed25519.Signature",
        "verifying.sha512_hash3",
        "ed25519.Signature.to_bytes",
        "signature.error.Error",
        "signature.error.Error.new",
    ],
    # anza same-crate extraction: the tightest cone
    "anza": [
        *STANDARD_LEAN_AXIOMS,
        "ed25519.Signature",
        "ed_sigs.sha512_hash3",
        "ed25519.Signature.r_bytes",
        "ed25519.Signature.s_bytes",
    ],
}

# The four apex tiers share the fork's boundary set exactly.
APEX_TIER_CERTIFICATES = [
    "CurveFieldProofs.verify_accepts_iff",
    "CurveFieldProofs.verify_accepts_iff_point",
    "CurveFieldProofs.verify_accepts_iff_point_eq",
    "CurveFieldProofs.verify_accepts_iff_decompress",
]

# Standard-three certificates below the apex (proven per fork).
STANDARD_CERTIFICATES = [
    "CurveFieldProofs.fieldImplementation",
    "CurveFieldProofs.edwardsImplementation",
    "ScalarProofs.scalarImplementation",
    "CurveFieldProofs.verify_loop_full",
    "CurveFieldProofs.to_bytes_spec",
    "CurveFieldProofs.ed_compress_spec",
    "ScalarProofs.from_bytes_mod_order_wide_spec",
    "CurveFieldProofs.vartime_dsm_basepoint_spec",
    "CurveFieldProofs.enc_point_inj",
    "CurveFieldProofs.sqrt_ratio_i_sq_spec",
    "CurveFieldProofs.from_bytes_spec",
    "CurveFieldProofs.decompress_of_canonical",
]

# What R4 requires: the full four-tier apex plus the constructive chain
# underneath it. R3 remains reachable from the arithmetic pair alone.
R4_REQUIREMENTS = [
    "CurveFieldProofs.fieldImplementation",
    "CurveFieldProofs.edwardsImplementation",
    "ScalarProofs.scalarImplementation",
    "CurveFieldProofs.to_bytes_spec",
    "CurveFieldProofs.ed_compress_spec",
    "ScalarProofs.from_bytes_mod_order_wide_spec",
    "CurveFieldProofs.decompress_of_canonical",
    *APEX_TIER_CERTIFICATES,
]


def certificate_axioms_for_boundary(boundary: str | None) -> dict[str, list[str]]:
    """Per-certificate allowed axiom sets for an ed25519 fork.

    Certificates not listed here are expected to carry exactly the three
    standard Lean axioms. Apex-tier certificates carry exactly the fork's
    documented boundary - nothing more, nothing less.
    """
    if not boundary:
        return {}
    allowed = APEX_BOUNDARIES.get(boundary)
    if allowed is None:
        raise KeyError(
            f"Unknown apex boundary '{boundary}'. Known boundaries: {sorted(APEX_BOUNDARIES)}"
        )
    return {name: list(allowed) for name in APEX_TIER_CERTIFICATES}


ED25519_PROFILE = Profile(
    kind="ed25519",
    default_certificates=[*STANDARD_CERTIFICATES, *APEX_TIER_CERTIFICATES],
    axiom_imports=[
        "Proofs.FieldMain",
        "Proofs.EdMain",
        "Proofs.ScalarMain",
        "Proofs.ToBytesSpec",
        "Proofs.CompressSpec",
        "Proofs.ScalarPackSpec",
        "Proofs.DsmMulSpec",
        "Proofs.SigApexSpec",
        "Proofs.PointLiftSpec",
        "Proofs.PointEqSpec",
        "Proofs.DecompressSpec",
        "Proofs.FromBytesSpec",
        "Proofs.DecompressMain",
    ],
    r4_requirements=list(R4_REQUIREMENTS),
    guarantees=[
        "FieldElement51 arithmetic is checked through denotation over F_p, p = 2^255 - 19, for the configured backend.",
        "Complete twisted Edwards point-operation laws are checked under ExtValid and OnCurveExt invariants.",
        "Scalar arithmetic mod l (add, sub, Montgomery mul, wide hash-to-scalar reduction) is checked through denotation.",
        "Point compression emits the canonical encoding (to_bytes canonicity + compress semantics are certified).",
        "Point decompression is constructively certified: canonical encodings of valid on-curve points decompress to them (from_bytes exactness, sqrt_ratio_i even root, sign-bit selection).",
        "THE SIGNATURE APEX, four button-enforced tiers: the extracted verifier accepts iff compress([s]B - [k]A) = R byte-for-byte, iff R is the canonical encoding of [k](-A) + [s]B, iff any point canonically encoded by R equals it, and iff R decompresses to a valid on-curve point equal to it.",
        "Each apex tier's axiom cone is pinned to EXACTLY the fork's documented SHA-512/wire-format boundary by the repo's own check script.",
        "Panic and overflow freedom evidence applies under the stated limb-bound preconditions.",
    ],
    preconditions=[
        "Use the exact pinned source or a reviewed diff against the checked artifact.",
        "Use the configured serial/u64 backend unless another backend has its own certificate.",
        "Maintain limb bounds and representation invariants required by the Lean statements.",
        "Treat Charon/Aeneas translation faithfulness as trusted base, not as proven by this tool.",
        "Map the production entry point to the verified path explicitly (on anza: verify_sha512 = verify_dalek, NOT the default HEEA/Zebra verify()).",
    ],
    exclusions=[
        "SHA-512 itself is not verified; it enters the apex theorems as an opaque oracle with NO assumed properties (the theorems hold for whatever bytes it produces).",
        "Signature parse/filter outcomes are hypothesis-parametric: the apex tiers assume the wire parse succeeded; the parsers' own byte-level specs are separate work.",
        "Signing (key generation, nonce derivation, the signer) is out of scope; only verification is certified.",
        "Rust compiler correctness is out of scope.",
        "Charon/Aeneas translation faithfulness is out of scope.",
        "Side-channel resistance is out of scope.",
        "SIMD, AVX, hardware, zkVM, accelerator, and syscall paths are out of scope (extraction pins the serial path).",
        "Wallet policy, transaction construction, RPC, oracle, market, and LLM decision safety are out of scope.",
    ],
    trusted_base=[
        "Lean kernel and standard library axioms.",
        "Lake/Lean package resolution used for replay.",
        "Correctness of the shipped Rust-to-Lean translation artifact.",
        "Correct mapping from the production code path to the checked backend.",
        "The fork's documented apex boundary: the SHA-512 oracle and opaque wire-format types (enforced per certificate by the repo's check script).",
        "Operating system, filesystem, and subprocess execution environment.",
    ],
    deployment_constraints=[
        "Use exact pinned source or reviewed diff.",
        "Use verified serial/u64 backend only.",
        "Disable accelerator, syscall, hardware, SIMD, and AVX paths unless separately certified.",
        "Verification-side evidence only: keep signing/key custody behind HSM, MPC, or policy firewall.",
        "SHA-512 remains an unverified dependency; pin and monitor the hash implementation.",
        "Use ordinary tests and fuzzing at wire-parse, API, and transaction boundaries (parse specs are hypothesis-parametric).",
    ],
    invalidation_conditions=[
        "The deployed code path differs from the checked backend or source revision.",
        "A certificate stops compiling under the pinned Lean environment.",
        "A certificate's axiom cone deviates from its documented allowed set in either direction.",
        "Required invariants are not enforced before calling verified routines.",
        "The implementation uses accelerator or syscall paths not covered by the certificates.",
        "The production entry point stops mapping to the verified path (e.g. anza's default verify() is used instead of verify_dalek).",
    ],
    next_milestones=[
        "Byte-level specs for the wire parsers/filters (discharge the hypothesis-parametric parse assumptions).",
        "A verified SHA-512 (or a proof-carrying hash oracle) to shrink the boundary.",
        "Reproducible production builds and compiler/build assurance (toward R5).",
        "Side-channel and backend-specific assurance evidence (toward R5).",
        "Signing-side verification (nonce derivation, signer correctness).",
    ],
)
