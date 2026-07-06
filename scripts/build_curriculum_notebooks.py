from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent


ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK_DIR = ROOT / "notebooks"


def md(source: str) -> dict:
    return {
        "cell_type": "markdown",
        "metadata": {},
        "source": _lines(source),
    }


def code(source: str) -> dict:
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": _lines(source),
    }


def _lines(text: str) -> list[str]:
    stripped = dedent(text).strip("\n")
    if not stripped:
        return []
    return [line + "\n" for line in stripped.splitlines()]


def notebook(cells: list[dict]) -> dict:
    return {
        "cells": cells,
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3",
            },
            "language_info": {
                "name": "python",
                "pygments_lexer": "ipython3",
            },
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }


COURSE = {
    "00_course_map.ipynb": notebook(
        [
            md(
                """
                # PACTA Curriculum: From Zero to Hero

                This curriculum teaches proof-aware cryptographic tooling from first principles to a research-grade professional workflow. It is designed for undergraduate students who know some programming and discrete math, but have not yet worked with formal verification, Lean, certificate transparency, or autonomous-agent risk gates.

                The practical anchor is PACTA: Proof-Aware Crypto Tooling Agent. The goal is not to build a trading bot. The goal is to teach an agent, and the engineer supervising it, to ask:

                > Does this theorem cover the exact code path that will protect funds?

                The course takes that question seriously. Every notebook connects theory to a runnable artifact in this repository.
                """
            ),
            md(
                """
                ## Learning Objectives

                By the end of the sequence, a strong student should be able to:

                - Explain why cryptographic implementation proofs have theorem boundaries.
                - Distinguish formal proof evidence from tests, audits, marketing claims, and operational controls.
                - Read a PACTA claim card and understand its guarantees, preconditions, exclusions, trusted base, and risk level.
                - Reproduce a local Lean replay or diagnose why local replay is unavailable.
                - Perform a proof hygiene scan and explain why `sorry`, local axioms, and trivial theorem targets are dangerous.
                - Explain how a third-party proof-checking provider changes the trusted base.
                - Implement and verify RFC 9162-style Merkle inclusion and consistency proofs.
                - Explain why Signed Tree Heads need accountable signatures, why Ed25519 is useful here, and why ML-DSA requires a real backend.
                - Design policy gates that convert verification evidence into consequences.
                - Read R4 four-tier apex evidence, name its residual blockers, and write a research plan toward R5 production assurance.
                """
            ),
            md(
                """
                ## Prerequisites

                Recommended background:

                - Python basics: functions, dictionaries, lists, files, subprocesses.
                - Discrete math: modular arithmetic, induction, trees, hashes.
                - Basic cryptography vocabulary: public keys, signatures, hashes, finite fields.
                - Basic command-line usage on macOS or Linux.

                Not required at the start:

                - Lean.
                - Rust internals.
                - Elliptic curve implementation expertise.
                - Certificate transparency expertise.
                """
            ),
            code(
                """
                from pathlib import Path
                import sys

                repo_root = Path.cwd()
                if not (repo_root / "src" / "pacta").exists():
                    repo_root = repo_root.parent
                sys.path.insert(0, str(repo_root / "src"))

                print(repo_root)
                print((repo_root / "README.md").exists())
                """
            ),
            md(
                """
                ## Course Map

                1. `01_threat_model_and_truth_boundary.ipynb`
                   Learn the product problem, the security boundary, and the difference between verified arithmetic and verified wallets.

                2. `02_claim_cards_and_risk_model.ipynb`
                   Study PACTA claim cards, risk levels R0-R5, and how claim serialization supports machine decisions.

                3. `03_lean_replay_and_axiom_audit.ipynb`
                   Learn how local Lean replay works, why PACTA avoids transpilation, and what an axiom audit proves.

                4. `04_proof_hygiene_and_boundaries.ipynb`
                   Learn to scan proof artifacts for `sorry`, local `axiom`, trivial theorem statements, and missing manifest coverage.

                5. `05_third_party_attestation_provider.ipynb`
                   Learn how a proof-checking service can transform hard local verification into provider trust.

                6. `06_merkle_transparency_logs.ipynb`
                   Build the Merkle accumulator intuition behind inclusion proofs, consistency proofs, and Signed Tree Heads.

                7. `07_agent_consequences.ipynb`
                   Connect evidence to action: build a lower-layer Rust capsule only when policy gates pass.

                8. `08_capstone_research_program.ipynb`
                   Design a PhD-level roadmap for closing the gaps from R4 toward R5.

                9. `09_dogfood_verified_crypto.ipynb`

                   Eat your own dogfood: run the agent's own signature checks through the proven code path, and hold the post-quantum line honestly.

                ## The Ratchet Rule

                This course follows the same didactic contract as its companion book (*Verifying Cryptography with Lean 4*): **every load-bearing idea is worked at least twice** - once at napkin scale (trees of three leaves, toy claim cards you can score in your head) and once at real scale (the shipped R4 claim cards, real receipts, the real proven-path verifier), with nothing hidden in between. The napkin run teaches the moves; the real-size run proves the moves are the whole story. If a step ever feels like a leap, back up one cell: the smaller rung is there.
                """
            ),
            md(
                """
                ## Assessment Model

                Each notebook contains:

                - A lecture section for concepts.
                - A lab section with runnable code.
                - Checkpoints that force precise answers.
                - Exercises for mastery.
                - Research prompts for advanced students.

                The capstone asks students to produce a defensible assurance case, not a slogan.
                """
            ),
            md(
                """
                ## References

                - RFC 9162, Certificate Transparency Version 2.0: https://datatracker.ietf.org/doc/html/rfc9162
                - RFC 8032, Edwards-Curve Digital Signature Algorithm: https://datatracker.ietf.org/doc/html/rfc8032
                - NIST FIPS 204, Module-Lattice-Based Digital Signature Standard: https://csrc.nist.gov/pubs/fips/204/final
                - PACTA README: `../README.md`
                """
            ),
        ]
    ),
    "01_threat_model_and_truth_boundary.ipynb": notebook(
        [
            md(
                """
                # Lecture 1: Threat Model and Truth Boundary

                The motivating system is an autonomous economic agent that may move stablecoins. It faces two broad attack classes:

                1. Psychological or game-theoretic attacks that trick the agent into harmful financial actions.
                2. Implementation attacks against the cryptographic and tooling stack that protects keys, signatures, proofs, and policy gates.

                PACTA focuses on the second class. It does not decide trades, call RPC endpoints, manage custody, or build wallets. It evaluates formal-verification-enhanced tooling and decides whether a constrained component can be used in a funds-protecting path.
                """
            ),
            md(
                """
                ## Learning Objectives

                - Define a threat model for proof-aware cryptographic tooling.
                - Explain why lower-layer arithmetic proofs do not imply wallet safety.
                - State the strongest current Ed25519-family claim in theorem-boundary language.
                - List common exclusions that remain outside the proof artifact.
                - Explain why an autonomous agent needs consequences, not just reports.
                """
            ),
            md(
                """
                ## The Core Truth Boundary

                The strongest current Ed25519-family claim in this project is approximately:

                For selected curve25519-dalek / Solana-Ed25519-family Rust code paths already transpiled into Lean, the verified repositories contain Lean-checked certificates for field arithmetic over `F_p`, `p = 2^255 - 19`, and complete twisted Edwards point-operation laws, under explicit invariants and backend constraints.

                That is valuable. And since 2026-07-06 the corpus goes much further: all four ed25519 repositories carry a FOUR-TIER signature apex, button-enforced per fork, up to the full lift - the extracted verifier accepts iff the signature's R decompresses to a valid on-curve point equal to [k](-A)+[s]B. What it is still NOT: a wallet proof, a proof of SHA-512, a proof of the wire parsers (their outcomes are hypotheses), a signing-side proof, or a proof of all Solana transaction behavior. Naming both lists - what is proven and what is not - is the entire discipline of this course.
                """
            ),
            md(
                """
                ## Proven or High-Value Evidence

                A clean R3-style Ed25519 arithmetic result may cover:

                - FieldElement51 arithmetic over `F_p` through denotation.
                - Panic and overflow freedom under limb-bound preconditions.
                - Complete Edwards point operations under `ExtValid` and `OnCurveExt`.
                - Implementation laws through denotation.
                - Axiom audit expected to show only standard Lean axioms: `propext`, `Classical.choice`, `Quot.sound`.

                The exact theorem names matter. In the current target repos, important certificates include:

                - `CurveFieldProofs.fieldImplementation`
                - `CurveFieldProofs.edwardsImplementation`
                """
            ),
            md(
                """
                ## Explicit Exclusions

                Do not let a lower-layer theorem leak into claims about:

                - Full EdDSA signature verification.
                - Complete Scalar52 arithmetic unless separately proven.
                - SHA-512.
                - Encoding, decoding, and canonicality unless separately proven.
                - Rust compiler correctness.
                - Charon/Aeneas translation faithfulness.
                - Side-channel resistance.
                - SIMD, AVX, hardware, zkVM, accelerator, or syscall paths.
                - Wallet policy, transaction construction, RPC, chain, oracle, market, or LLM decision safety.

                A professional assurance case is often mostly about preventing evidence from being overextended.
                """
            ),
            code(
                """
                from pathlib import Path
                import sys

                repo_root = Path.cwd()
                if not (repo_root / "src" / "pacta").exists():
                    repo_root = repo_root.parent
                sys.path.insert(0, str(repo_root / "src"))

                from pacta.config import load_config

                config = load_config(repo_root / "examples" / "repos.yaml")
                for repo in config.repos:
                    print(f"{repo.name:32} kind={repo.kind:13} backend={repo.verified_backend}")
                    if repo.backend_warning:
                        print(f"  backend warning: {repo.backend_warning}")
                    if repo.known_status:
                        print(f"  known status: {repo.known_status}")
                """
            ),
            md(
                """
                ## Consequences

                PACTA turns evaluation into operational consequences:

                - If evidence is R0/R1/R2, do not build or consume lower-layer crypto capsules.
                - If evidence is R3, a constrained lower-layer component capsule may be built.
                - If evidence is below R4, wallet demo construction is refused.
                - If a third-party attestation is required but not trusted, the score falls to R0.
                - If a transparency receipt is required but invalid or absent, the score falls to R0.

                This makes verification a gate, not a decorative badge.
                """
            ),
            md(
                """
                ## Checkpoint Questions

                1. Why does a proof of field arithmetic not prove transaction construction?
                2. What would have to be proven before full EdDSA verification could plausibly reach R4?
                3. Why is "the proof failed to replay locally" different from "the theorem is false"?
                4. Why should a zkVM accelerator path be excluded unless the repo proves otherwise?
                """
            ),
            md(
                """
                ## Exercises

                - Pick one configured repository from `examples/repos.yaml`. Write three precise claims that PACTA may make about it and three claims PACTA must refuse.
                - Rewrite the sentence "this is verified Ed25519" into a theorem-boundary statement that a security reviewer would accept.
                - Create a table mapping each exclusion above to the attack class it leaves open.
                """
            ),
        ]
    ),
    "02_claim_cards_and_risk_model.ipynb": notebook(
        [
            md(
                """
                # Lecture 2: Claim Cards and the R0-R5 Risk Model

                A claim card is a machine-readable assurance artifact. It records what was checked, what theorem names were involved, what axioms were observed, what exclusions remain, what trusted base is assumed, and what risk score follows.

                A claim card is not a marketing page. It is a structured input to policy.
                """
            ),
            md(
                """
                ## Learning Objectives

                - Read the claim card schema.
                - Explain risk levels R0 through R5.
                - Generate an offline fixture claim card.
                - Understand why R3 can authorize lower-layer library use but not wallet construction.
                - Identify blockers and deployment constraints in a claim card.
                """
            ),
            md(
                """
                ## Risk Levels

                - `R0`: Unknown or untrusted. No usable evidence.
                - `R1`: Tests, audits, or informal claims only.
                - `R2`: Formal model exists, but incomplete, weakly tied to production code, or major proof gaps remain.
                - `R3`: A specific lower-layer implementation artifact is Lean-checked for a specific backend and theorem boundary.
                - `R4`: End-to-end primitive proof covers public API, parsing/encoding, scalar arithmetic, hashing interface, signature equation, rejection rules, and implementation boundary.
                - `R5`: R4 plus reproducible production builds, compiler/build assurance, side-channel analysis, hardware/KMS/MPC integration, and operational controls.

                Ed25519 field plus Edwards arithmetic alone reaches R3. Since the corpus completed its four-tier signature apex (2026-07-06), the FULL configured certificate set - arithmetic, scalars, encoding/decoding, and the four apex tiers, each with its axiom cone pinned to the fork's documented boundary - reaches **R4**, always with explicit residual blockers (the SHA-512 oracle, hypothesis-parametric wire parses, translation faithfulness, and the missing side-channel/build assurance that gates R5).
                """
            ),
            code(
                """
                from pathlib import Path
                import sys

                repo_root = Path.cwd()
                if not (repo_root / "src" / "pacta").exists():
                    repo_root = repo_root.parent
                sys.path.insert(0, str(repo_root / "src"))

                from pacta.claims import build_claim_card
                from pacta.config import load_config

                config = load_config(repo_root / "examples" / "repos.yaml")
                repo = config.repo_named("dalek-ed25519-verified")
                card = build_claim_card(repo, repo_root / "repos" / repo.name, offline_fixture=True)

                print(card["component"])
                print(card["risk"]["level"])
                print(card["risk"]["rationale"])
                print(card["certificates"][0])
                """
            ),
            code(
                """
                important_fields = [
                    "component",
                    "repo_url",
                    "repo_commit",
                    "verification_dir",
                    "kind",
                    "verified_backend",
                    "certificates",
                    "guarantees",
                    "preconditions",
                    "exclusions",
                    "trusted_base",
                    "evidence",
                    "risk",
                ]
                for field in important_fields:
                    print(field, "=>", type(card.get(field)).__name__)
                """
            ),
            md(
                """
                ## Reading a Certificate Entry

                A certificate entry contains:

                - `name`: theorem or aggregate certificate name.
                - `status`: `proven`, `missing`, `failed`, or `unknown`.
                - `axiom_status`: `clean`, `dirty`, or `not_checked`.
                - `observed_axioms`: axioms reported by Lean.
                - `expected_axioms`: allowed standard axioms for this profile.

                A clean result requires more than a theorem name. It requires a successful replay or trusted attestation, the RIGHT axiom set per certificate (standard-three below the apex, the fork's documented boundary at the apex tiers - deviation in either direction is dirty), and no policy-blocking exclusions.

                ### The ratchet, run both ways

                First the napkin: a two-certificate card you can score in your head. Then the real thing: the shipped R4 fixture with sixteen certificates and per-tier boundary axioms.
                """
            ),
            code(
                """
                # NAPKIN: an arithmetic-only card. Two certificates, standard axioms.
                from pacta.risk import score_claim_card

                napkin_card = {
                    "kind": "ed25519",
                    "certificates": [
                        {"name": "CurveFieldProofs.fieldImplementation", "status": "proven", "axiom_status": "clean"},
                        {"name": "CurveFieldProofs.edwardsImplementation", "status": "proven", "axiom_status": "clean"},
                    ],
                    "exclusions": ["full EdDSA signature verification"],
                    "meta": {"r4_requirements": []},
                }
                napkin = score_claim_card(napkin_card)
                print(napkin.level, "-", napkin.rationale)
                """
            ),
            code(
                """
                # REAL: the shipped R4 fixture - sixteen certificates, apex tiers carrying
                # the dalek fork's documented boundary axioms. Same scoring function.
                from pacta.yamlio import load_data

                real_card = load_data(repo_root / "examples" / "dalek-ed25519.claims.yaml")
                real = score_claim_card(real_card)
                print(real.level)
                print(real.rationale[:180], "...")
                print("residual blockers:")
                for blocker in real.blockers:
                    print(" -", blocker)
                apex = [c for c in real_card["certificates"] if c["name"].endswith("_decompress")][0]
                print("full-lift tier expects:", apex["expected_axioms"])
                """
            ),
            code(
                """
                for cert in card["certificates"]:
                    print(f"{cert['name']}: {cert['status']} / {cert['axiom_status']}")
                    print("  observed:", cert["observed_axioms"])
                    print("  expected:", cert["expected_axioms"])
                """
            ),
            md(
                """
                ## Deployment Constraints

                Deployment constraints are where many assurance cases become honest. For Ed25519 arithmetic, constraints include:

                - Use exact pinned source or reviewed diff.
                - Use verified serial/u64 backend only.
                - Disable accelerator/syscall/hardware/SIMD paths unless separately certified.
                - Do not treat this as full EdDSA verification.
                - Keep key custody behind HSM/MPC/policy firewall until signing stack proof coverage improves.
                - Use ordinary tests/fuzzing at encoding/API/transaction boundaries.
                """
            ),
            code(
                """
                for constraint in card["risk"]["deployment_constraints"]:
                    print("-", constraint)
                """
            ),
            md(
                """
                ## Exercises

                - Change the generated card in memory so one certificate is `missing`. Rescore it and explain the change.
                - Write a short policy that allows `build-library` at R3 but denies `build-wallet-demo` below R4.
                - Compare the trusted base for local replay versus third-party attestation.
                """
            ),
            code(
                """
                from copy import deepcopy
                from pacta.risk import score_claim_card

                weaker = deepcopy(card)
                weaker["certificates"][0]["status"] = "missing"
                weaker["certificates"][0]["axiom_status"] = "not_checked"
                assessment = score_claim_card(weaker)
                print(assessment.level)
                print(assessment.rationale)
                print(assessment.blockers)
                """
            ),
        ]
    ),
    "03_lean_replay_and_axiom_audit.ipynb": notebook(
        [
            md(
                """
                # Lecture 3: Lean Replay and Axiom Audit

                The verified repositories already contain Lean artifacts. PACTA does not run Charon, Aeneas, extraction, or Rust-to-Lean regeneration. It treats shipped Lean files as the verification artifact and focuses on replaying and inspecting them.
                """
            ),
            md(
                """
                ## Learning Objectives

                - Explain the difference between transpilation and proof replay.
                - Understand how PACTA discovers Lean files and manifests.
                - Build a portable Lean invocation without Linux-only shell helpers.
                - Explain `#print axioms` and why axiom sets matter.
                - Diagnose missing Lean/lake or missing pinned Aeneas environments.
                """
            ),
            md(
                """
                ## Why Not Run Charon/Aeneas?

                The corpus policy is strict:

                - The transpilation work is finished in the verified repos.
                - Re-running extraction could create a different artifact and confuse the trust story.
                - The current task is to interpret, replay, summarize, and score the existing Lean proof artifacts.

                For a production assurance case, translation faithfulness remains part of the trusted base unless separately proven.
                """
            ),
            code(
                """
                from pathlib import Path
                import sys

                repo_root = Path.cwd()
                if not (repo_root / "src" / "pacta").exists():
                    repo_root = repo_root.parent
                sys.path.insert(0, str(repo_root / "src"))

                from pacta.manifest import discover_layout

                fixture = repo_root / "tests" / "fixtures" / "mini-ed25519-verified"
                layout = discover_layout(fixture, "verification")
                print("verification_dir:", layout.verification_dir)
                print("files:")
                for path in layout.compile_order:
                    print(" ", path.relative_to(fixture))
                print("warnings:", layout.warnings)
                """
            ),
            md(
                """
                ## Portable Lean Invocation

                PACTA avoids repository `check.sh` scripts because those may assume Linux-only tools like `free`, `taskset`, or GNU `timeout`. Instead it uses Python `subprocess.run(..., timeout=...)` and constructs a Lean environment where `verification/gen` and `verification` are visible through `LEAN_PATH`.

                If a pinned Aeneas Lean project is needed, PACTA can source a configured environment script and run `lake env lean`. It still does not run extraction.
                """
            ),
            code(
                """
                from pacta.lean import LeanTools, build_lean_invocation

                tools = LeanTools(lean="/usr/bin/lean", lake="/usr/bin/lake")
                example_file = layout.compile_order[0]
                print(build_lean_invocation(example_file, tools, use_lake_env=True, output_path=example_file.with_suffix(".olean")))
                """
            ),
            md(
                """
                ## Axiom Audit

                A theorem can compile while depending on unexpected axioms. For the Ed25519 arithmetic profiles, the expected axiom set is usually:

                - `propext`
                - `Classical.choice`
                - `Quot.sound`

                PACTA generates a temporary Lean file with imports such as:

                ```lean
                import Proofs.FieldMain
                import Proofs.EdMain
                #print axioms CurveFieldProofs.fieldImplementation
                #print axioms CurveFieldProofs.edwardsImplementation
                ```

                It then parses Lean output and marks the result clean only when observed axioms match the expected set.
                """
            ),
            code(
                """
                from pacta.lean import parse_axiom_output

                output = \"\"\"'CurveFieldProofs.fieldImplementation' depends on axioms:
                [propext, Classical.choice, Quot.sound]
                'CurveFieldProofs.edwardsImplementation' depends on axioms:
                [propext, Classical.choice, Quot.sound]
                \"\"\"
                parsed = parse_axiom_output(
                    output,
                    [
                        "CurveFieldProofs.fieldImplementation",
                        "CurveFieldProofs.edwardsImplementation",
                    ],
                )
                print(parsed)
                """
            ),
            md(
                """
                ## Local Replay Failure Modes

                Important distinctions:

                - Missing `lean`: local verifier capability unavailable.
                - Missing `lake`: local project environment may be unavailable.
                - Missing Aeneas Lean project: local replay unavailable for repos that depend on it.
                - Lean file fails: proof replay failed in this environment.
                - Axiom set dirty: theorem depends on unexpected assumptions.

                These are not the same. A professional report must state which one happened.
                """
            ),
            md(
                """
                ## Exercises

                - Run `pacta doctor --config examples/repos.yaml --repo-name dalek-ed25519-verified` and classify the result.
                - Create a fake axiom output with an extra axiom. Parse it and explain why the result should be dirty.
                - Explain why a replay runner should not silently fall back from failure to an offline fixture.
                """
            ),
        ]
    ),
    "04_proof_hygiene_and_boundaries.ipynb": notebook(
        [
            md(
                """
                # Lecture 4: Proof Hygiene and Boundaries

                Proof hygiene is the discipline of checking whether formal artifacts have obvious escape hatches or misleading theorem surfaces. It does not replace proof checking. It catches common ways a proof corpus can look stronger than it is.
                """
            ),
            md(
                """
                ## Learning Objectives

                - Detect `sorry`, local `axiom`, trivial theorem targets, and suspicious `by trivial`.
                - Understand why comments should not be treated as fatal proof failures.
                - Explain why manifest coverage matters.
                - Distinguish a hygiene warning from a replay failure.
                - Write precise boundary language for proof reports.
                """
            ),
            md(
                """
                ## Patterns PACTA Scans For

                - `sorry`
                - `axiom` declarations under `Proofs/`
                - theorem targets such as `: True :=`
                - suspicious `by trivial` in spec/certificate/root files
                - `native_decide` as advisory unless dependency-cone analysis is stronger
                - missing certificate names
                - proof files not included in a manifest when a manifest exists

                A simple scanner may over-warn. It must not over-claim.
                """
            ),
            code(
                """
                from pathlib import Path
                import sys

                repo_root = Path.cwd()
                if not (repo_root / "src" / "pacta").exists():
                    repo_root = repo_root.parent
                sys.path.insert(0, str(repo_root / "src"))

                from pacta.audit import scan_hygiene
                from pacta.manifest import discover_layout

                fixture = repo_root / "tests" / "fixtures" / "mini-ed25519-verified"
                layout = discover_layout(fixture, "verification")
                issues = scan_hygiene(layout, ["CurveFieldProofs.fieldImplementation"])
                print("issues:", issues)
                """
            ),
            md(
                """
                ## Why `sorry` Is Serious

                In Lean, `sorry` can stand in for a proof. Depending on settings, it may allow a theorem to exist without its proof being completed. In a verification-evidence pipeline, unresolved `sorry` must block high-confidence claims.

                The lesson is not "never prototype with placeholders." The lesson is "never ship assurance claims that hide placeholders."
                """
            ),
            md(
                """
                ## Why Local Axioms Are Serious

                A local axiom can assert the result directly. For example:

                ```lean
                axiom fieldImplementation : CorrectFieldImplementation
                ```

                That may be useful for bootstrapping a model, but it is not proof evidence for implementation correctness. PACTA flags local axioms under `Proofs/` because they may collapse the intended theorem into an assumption.
                """
            ),
            md(
                """
                ## Trivial Theorems and Spec Drift

                A theorem target like `: True := by trivial` proves exactly nothing about cryptographic code. A more subtle failure is spec drift: the theorem proves a property, but not the property the system needs.

                Professional review asks two questions:

                1. Is the proof complete?
                2. Is the theorem the right theorem?
                """
            ),
            code(
                """
                # A tiny reviewer helper: classify theorem statements by obvious risk.
                examples = {
                    "good_shape": "theorem add_denote ... : denote (add x y) = x + y := ...",
                    "trivial_target": "theorem certificate : True := by trivial",
                    "placeholder": "theorem hard_part : P := by sorry",
                }

                for name, text in examples.items():
                    flags = []
                    if "sorry" in text:
                        flags.append("placeholder proof")
                    if ": True :=" in text:
                        flags.append("trivial target")
                    if "by trivial" in text:
                        flags.append("trivial proof tactic")
                    print(name, flags or ["needs semantic review"])
                """
            ),
            md(
                """
                ## Exercises

                - Add a temporary Lean file under a scratch fixture with a theorem `: True := by trivial`. Run the scanner and inspect the issue.
                - Explain why the same word in a comment should not be fatal by itself.
                - Write a one-page checklist for reviewing a new `*-verified` repository before assigning any risk score above R2.
                """
            ),
        ]
    ),
    "05_third_party_attestation_provider.ipynb": notebook(
        [
            md(
                """
                # Lecture 5: Third-Party Proof-Checking Attestations

                Local proof replay can be operationally cumbersome. A specialized provider can run the Lean/Aeneas environment in a controlled setup and publish a signed attestation. This transforms trust in local compilation into trust in a provider, its environment, its signing key custody, and its transparency log.
                """
            ),
            md(
                """
                ## Learning Objectives

                - Explain the trust transformation from local replay to provider attestation.
                - Read a provider attestation.
                - Verify an Ed25519 attestation signature.
                - Understand why untrusted attestations must score R0.
                - Distinguish a provider signature from transparency-log accountability.
                """
            ),
            md(
                """
                ## Attestation Contents

                A useful attestation records:

                - provider identity,
                - issue time,
                - subject component, repo URL, repo commit, verification dir, kind, backend,
                - Lean and lake versions,
                - check log and axiom log locations,
                - certificate names, statuses, observed axioms, expected axioms,
                - provider signature metadata.

                The agent must verify both content and trust policy. A valid signature from an untrusted provider is not enough.
                """
            ),
            code(
                """
                from pathlib import Path
                import sys

                repo_root = Path.cwd()
                if not (repo_root / "src" / "pacta").exists():
                    repo_root = repo_root.parent
                sys.path.insert(0, str(repo_root / "src"))

                from pacta.attestation import load_attestation

                attestation_path = repo_root / "examples" / "dalek-ed25519.attestation.yaml"
                raw = load_attestation(attestation_path)
                print(raw.keys())
                print(raw["provider"])
                print(raw["subject"])
                print(raw["certificates"][0])
                """
            ),
            md(
                """
                ## Trust Policy

                PACTA requires an explicit `--trust-attestation-provider` value. If the attestation provider does not match, the attestation is rejected.

                Real attestations should be signed. The included example fixture is unsigned and requires `--allow-unsigned-attestation`, which is suitable only for demos and tests.
                """
            ),
            code(
                """
                from pacta.attestation import validate_attestation
                from pacta.config import RepoConfig

                repo = RepoConfig(
                    name="dalek-ed25519-verified",
                    url="https://github.com/saymrwulf/dalek-ed25519-verified.git",
                    kind="ed25519",
                    verified_backend="serial/u64",
                    certificates=[
                        "CurveFieldProofs.fieldImplementation",
                        "CurveFieldProofs.edwardsImplementation",
                    ],
                )

                trusted = validate_attestation(
                    raw,
                    repo,
                    path=attestation_path,
                    trusted_provider="example-proof-checker.invalid",
                    allow_unsigned=True,
                )
                untrusted = validate_attestation(raw, repo, path=attestation_path)
                print("trusted accepted:", trusted.accepted)
                print("untrusted accepted:", untrusted.accepted)
                print("untrusted diagnostics:", untrusted.diagnostics)
                """
            ),
            md(
                """
                ## Provider Threat Model

                A proof-checking provider can be valuable, but it introduces new risks:

                - It may sign an incorrect result.
                - Its environment may be stale or compromised.
                - Its signing key may be stolen.
                - It may equivocate by showing different results to different agents.
                - It may lose log history.

                This is why transparency logging matters. A signature says "this provider signed this." A transparency receipt says "this signed result is included in an append-only public structure at this tree head."
                """
            ),
            md(
                """
                ## Real evidence, checked in this cell

                Everything above used schema fixtures. The repository now ships REAL provider evidence under `evidence/`: signed attestations from a guarded Lean replay of all four verified repositories (~30 minutes of kernel re-checking per fork), each recording the repo commit, the machine-protection block, and all sixteen certificates with their observed axiom cones. Read one and re-derive its verdicts locally - never trust the provider's own labels:
                """
            ),
            code(
                """
                from pacta.attestation import load_attestation, _normalize_certificate
                from pacta.config import load_config
                from pacta.profiles import get_profile
                from pacta.signing import verify_attestation_signature_detailed

                config = load_config(repo_root / "examples" / "repos.yaml")
                repo = config.repo_named("dalek-ed25519-verified")
                profile = get_profile("ed25519", repo)
                att = load_attestation(repo_root / "evidence" / "dalek-ed25519.attestation.yaml")

                ok, error, backend = verify_attestation_signature_detailed(att, repo_root / "evidence" / "provider.ed25519.pub")
                print("signature valid:", ok, "| verified on backend:", backend)
                print("subject commit:", att["subject"]["repo_commit"][:12])
                print("machine protection:", att["machine_protection"]["lean_guard"].rsplit("/", 2)[-1])

                rederived = [_normalize_certificate(cert, profile) for cert in att["certificates"]]
                clean = sum(1 for cert in rederived if cert["status"] == "proven" and cert["axiom_status"] == "clean")
                print(f"re-derived locally: {clean}/{len(rederived)} proven with boundary-exact cones")
                apex = [cert for cert in rederived if cert["name"].endswith("_decompress")][0]
                print("full-lift tier observed cone:", apex["observed_axioms"])
                """
            ),
            md(
                """
                ## Exercises

                - Draw the trusted base for local replay and provider attestation. Mark what changes.
                - Explain why a provider attestation must include repo commit, not only repo name.
                - Design a monitoring rule that would detect if the provider changes the result for the same commit.
                """
            ),
        ]
    ),
    "06_merkle_transparency_logs.ipynb": notebook(
        [
            md(
                """
                # Lecture 6: Merkle Transparency Logs

                Transparency logs make signed statements auditable. PACTA uses an RFC 9162-style Merkle accumulator over signed proof-check attestations. A provider signs the tree head, and an agent verifies an inclusion proof before acting on the attestation.
                """
            ),
            md(
                """
                ## Learning Objectives

                - Implement leaf and node hashing with domain separation.
                - Compute a Merkle root.
                - Generate and verify inclusion proofs.
                - Generate and verify consistency proofs.
                - Explain Signed Tree Heads and signature policy.
                - Explain why ML-DSA must fail closed when unavailable.
                """
            ),
            md(
                """
                ## RFC 9162 Hash Shape

                PACTA follows the Certificate Transparency hash structure:

                - Empty tree hash: `SHA256("")`
                - Leaf hash: `SHA256(0x00 || leaf_input)`
                - Node hash: `SHA256(0x01 || left || right)`

                The prefix bytes prevent a leaf value from being confused with an internal node value.
                """
            ),
            code(
                """
                from pathlib import Path
                import sys

                repo_root = Path.cwd()
                if not (repo_root / "src" / "pacta").exists():
                    repo_root = repo_root.parent
                sys.path.insert(0, str(repo_root / "src"))

                from pacta.transparency import (
                    leaf_hash,
                    node_hash,
                    merkle_root,
                    inclusion_proof,
                    verify_inclusion,
                    consistency_proof,
                    verify_consistency,
                )

                leaves = [f"attestation-{i}".encode() for i in range(1, 6)]
                root = merkle_root(leaves)
                print(root.hex())
                """
            ),
            code(
                """
                for index, leaf in enumerate(leaves):
                    proof = inclusion_proof(leaves, index)
                    ok = verify_inclusion(leaf, index, len(leaves), proof, root)
                    print(index, ok, [node.hex()[:12] for node in proof])
                """
            ),
            md(
                """
                ## Consistency Proofs

                An inclusion proof answers: "Is this leaf in this tree?"

                A consistency proof answers: "Is the newer tree an append-only extension of the older tree?"

                Both are needed for a monitored transparency system. Inclusion is enough for one agent to bind one attestation to one signed tree head. Consistency lets monitors detect equivocation or tree rewrites across time.
                """
            ),
            code(
                """
                old_size = 3
                old_root = merkle_root(leaves[:old_size])
                new_root = merkle_root(leaves)
                proof = consistency_proof(leaves, old_size)
                print("old:", old_root.hex())
                print("new:", new_root.hex())
                print("proof:", [node.hex()[:12] for node in proof])
                print("consistent:", verify_consistency(old_size, len(leaves), old_root, new_root, proof))
                """
            ),
            md(
                """
                ## Signed Tree Heads

                A Signed Tree Head records:

                - log ID,
                - tree size,
                - timestamp,
                - root hash,
                - hash algorithm,
                - signatures.

                PACTA signs the canonical JSON STH payload with Ed25519 through OpenSSL. It also records an ML-DSA-65 slot. On this host, if no real ML-DSA backend is present, the slot is `unavailable`.

                Policy matters:

                - `require-signatures ed25519`: verify Ed25519 and allow ML-DSA to be unavailable.
                - `require-signatures both`: require Ed25519 and ML-DSA verified. If ML-DSA is unavailable, fail closed.
                """
            ),
            code(
                """
                from pacta.postquantum import detect_ml_dsa

                capability = detect_ml_dsa()
                print(capability.available)
                print(capability.backend)
                print(capability.reason)
                """
            ),
            md(
                """
                ## Why Ed25519 and ML-DSA Together?

                Ed25519 is useful because it is widely deployed, fast, and directly relevant to the Ed25519 proof corpus. That creates a deliberate "eat your own dogfood" loop: the proof-checking ecosystem signs evidence using a primitive whose implementation family is under formal scrutiny.

                ML-DSA adds post-quantum robustness for the accumulator signature layer. But it must be a real signature, not an aspirational label. If a host lacks ML-DSA, the correct result is an explicit blocker.
                """
            ),
            md(
                """
                ## Split Views: why a receipt is not enough

                Everything above verifies ONE receipt against ONE signed tree head. A malicious provider can maintain TWO trees - one shown to you, one shown to the world - and both views verify perfectly in isolation. This is EQUIVOCATION, and the defense is memory: pin every tree head you accept, and demand that every later tree head be CONSISTENT with your pin (same size -> same root; larger size -> a verified consistency proof from your pinned size; smaller size -> rollback, reject forever).

                pacta implements this as a local STH pin store. Run the whole attack and its detection, napkin-size:
                """
            ),
            code(
                """
                # NAPKIN: pin a 2-leaf view, then let the log grow honestly - and then
                # let a SPLIT VIEW present a different root at the pinned size.
                import tempfile
                from pathlib import Path as _P
                from pacta.sthstore import check_sth_against_store
                from pacta.transparency import consistency_proof, merkle_root, proof_to_hex

                honest = [b"attestation-A", b"attestation-B", b"attestation-C"]
                evil = [b"attestation-A", b"attestation-EVIL", b"attestation-C"]

                with tempfile.TemporaryDirectory() as tmp:
                    store = _P(tmp) / "sth-store.json"
                    sth = lambda size, leaves: {
                        "log_id": "demo-log", "tree_size": size,
                        "root_hash": merkle_root(leaves[:size]).hex(),
                        "timestamp": "2026-07-06T00:00:00Z",
                    }
                    print("pin:     ", check_sth_against_store(sth(2, honest), store).diagnostics[0])
                    grown = check_sth_against_store(
                        sth(3, honest), store,
                        consistency_proof_hex=proof_to_hex(consistency_proof(honest, 2)),
                    )
                    print("grow:    ", grown.diagnostics[0])
                    attack = check_sth_against_store(sth(3, evil), store)
                    print("attack ok?", attack.ok)
                    print("verdict: ", attack.diagnostics[0][:120], "...")
                """
            ),
            md(
                """
                At real scale the same check runs on every `pacta receipt-verify --sth-store ...` and `pacta agent --sth-store ...` invocation; receipts embed a consistency anchor from the previous tree size, the provider serves proofs from arbitrary pinned sizes (`pacta_provider log-consistency --from-size N`), and `pacta_provider log-audit` is the monitor's self-check. A freshness policy (`--max-sth-age-seconds`) closes the stale-root hole: an old-but-valid tree head could hide later entries.

                ### The real thing

                The `evidence/` directory holds four REAL receipts from the shipped transparency log (tree size 8 - the first four leaves honestly record a failed audit run; read `evidence/README.md`). Verify all four cryptographically and watch a fresh pin store handle them:
                """
            ),
            code(
                """
                import tempfile
                from pathlib import Path as _P
                from pacta.sthstore import check_sth_against_store
                from pacta.transparency import verify_receipt
                from pacta.yamlio import load_data as _load

                log_key = repo_root / "evidence" / "provider.ed25519.pub"
                with tempfile.TemporaryDirectory() as tmp:
                    store = _P(tmp) / "pins.json"
                    for fork in ["dalek", "anza", "risc0", "betrusted"]:
                        att = _load(repo_root / "evidence" / f"{fork}-ed25519.attestation.yaml")
                        receipt = _load(repo_root / "evidence" / f"{fork}-ed25519.receipt.yaml")
                        result = verify_receipt(att, receipt, log_key)
                        pin = check_sth_against_store(receipt["sth"], store, consistency_from=receipt.get("consistency"))
                        print(f"{fork}: receipt accepted={result.accepted} backend={result.signatures.get('ed25519_backend')} pin={pin.action}")
                """
            ),
            md(
                """

                ## Exercises

                - Tamper with one leaf and show that inclusion verification fails.
                - Explain why the tree head signature must cover tree size as well as root hash.
                - Napkin, then real: run the split-view drill above; then initialize a real provider log (`pacta_provider log-init`), append two attestations, and verify the second receipt with `--sth-store` - watch the pin advance with a verified consistency proof.
                - Why must the consistency anchor's ROOT (not just its size) be checked against the pin? Construct the lie that a size-only check would miss.
                - Write a policy for when an autonomous agent should require `both` signatures.
                - Research checkpoint: compare PACTA's pin store to production Certificate Transparency monitor/gossip requirements - what does gossip add that a single pin store cannot?
                """
            ),
        ]
    ),
    "07_agent_consequences.ipynb": notebook(
        [
            md(
                """
                # Lecture 7: Agent Consequences

                An evidence interpreter is incomplete if nothing changes after evaluation. PACTA has a small consequence engine: it can build a lower-layer Rust decision capsule when evidence satisfies policy, and it refuses wallet construction when coverage is insufficient.
                """
            ),
            md(
                """
                ## Learning Objectives

                - Explain how risk levels map to actions.
                - Run a dry-run agent action.
                - Understand the generated Rust capsule.
                - Explain why R3 permits lower-layer use but denies wallet demos.
                - Run the gate both ways: a partial (arithmetic-only) card is denied; the full four-tier card is allowed.
                - Connect transparency receipts to build authorization.
                """
            ),
            md(
                """
                ## Action Policy

                Current actions:

                - `build-library`: default threshold R3. Produces a proof-gated component capsule.
                - `build-wallet-demo`: threshold R4. Writes a denial artifact below R4 - and since the corpus completed its four-tier apex, R4 evidence EXISTS, so this gate can now legitimately open. Watch it swing both ways below.

                This is deliberately conservative. The theorem boundary for Ed25519 field plus Edwards arithmetic is valuable, but it does not cover key custody, encoding, hashing, scalar arithmetic completeness, signature verification, transaction construction, or market decisions.
                """
            ),
            code(
                """
                from pathlib import Path
                import sys

                repo_root = Path.cwd()
                if not (repo_root / "src" / "pacta").exists():
                    repo_root = repo_root.parent
                sys.path.insert(0, str(repo_root / "src"))

                from pacta.agent import run_agent_action
                from pacta.claims import build_claim_card
                from pacta.config import load_config

                repo = load_config(repo_root / "examples" / "repos.yaml").repo_named("dalek-ed25519-verified")
                card = build_claim_card(repo, repo_root / "repos" / repo.name, offline_fixture=True)

                library_decision = run_agent_action(card, "build-library", repo_root / "artifacts-notebook", dry_run=True)
                wallet_decision = run_agent_action(card, "build-wallet-demo", repo_root / "artifacts-notebook", dry_run=True)
                print(library_decision.to_dict())
                print(wallet_decision.to_dict())
                """
            ),
            code(
                """
                # NAPKIN: an arithmetic-only card faces the wallet gate - DENIED.
                from pathlib import Path
                import sys, tempfile

                repo_root = Path.cwd()
                if not (repo_root / "src" / "pacta").exists():
                    repo_root = repo_root.parent
                sys.path.insert(0, str(repo_root / "src"))

                from pacta.agent import run_agent_action
                from pacta.risk import score_claim_card

                partial = {
                    "component": "napkin-arithmetic-only",
                    "kind": "ed25519",
                    "certificates": [
                        {"name": "CurveFieldProofs.fieldImplementation", "status": "proven", "axiom_status": "clean"},
                        {"name": "CurveFieldProofs.edwardsImplementation", "status": "proven", "axiom_status": "clean"},
                    ],
                    "exclusions": ["full EdDSA signature verification"],
                    "meta": {"r4_requirements": []},
                }
                partial["risk"] = score_claim_card(partial).to_dict()
                with tempfile.TemporaryDirectory() as tmp:
                    decision = run_agent_action(partial, "build-wallet-demo", tmp, dry_run=True)
                    print("allowed:", decision.allowed, "at", decision.risk_level)
                    print(decision.rationale)
                """
            ),
            code(
                """
                # REAL: the shipped four-tier R4 card faces the same gate - ALLOWED
                # (a demo scaffold only; the residual blockers ride along in the card).
                from pacta.yamlio import load_data

                full = load_data(repo_root / "examples" / "dalek-ed25519.claims.yaml")
                with tempfile.TemporaryDirectory() as tmp:
                    decision = run_agent_action(full, "build-wallet-demo", tmp, dry_run=True)
                    print("allowed:", decision.allowed, "at", decision.risk_level)
                    print(decision.rationale)
                """
            ),
            md(
                """
                ## The Rust Capsule

                The generated capsule is not cryptographic code. It is a consumable policy artifact. It embeds the claim card and exposes constants such as:

                - component,
                - repo URL,
                - kind,
                - verified backend,
                - risk level,
                - evidence mode,
                - attestation provider,
                - deployment constraints.

                Downstream automation can import this crate and check `allowed_for_lower_layer_crypto()` before enabling a code path.
                """
            ),
            code(
                """
                from pacta.artifact import _lib_rs

                print(_lib_rs(card).splitlines()[:24])
                """
            ),
            md(
                """
                ## Receipt-Required Builds

                The strongest dogfood path in this prototype is:

                1. Provider replays Lean and signs attestation.
                2. Provider appends attestation to a Merkle transparency log.
                3. Provider emits an inclusion receipt with Signed Tree Head.
                4. Agent verifies provider signature, receipt inclusion proof, and STH signature.
                5. Agent builds only if risk and transparency policy pass.

                This transforms "I read a report" into "I accepted a logged, signed proof-check result and acted within its theorem boundary."
                """
            ),
            md(
                """
                ## Command-Line Lab

                Run these from the repository root after generating a provider attestation:

                ```bash
                pacta receipt-verify \\
                  --attestation provider/out/dalek-ed25519.attestation.yaml \\
                  --receipt provider/out/dalek-ed25519.receipt.yaml \\
                  --log-public-key provider/state/local-provider/provider.ed25519.pub

                pacta agent \\
                  --config examples/repos.yaml \\
                  --repo-name dalek-ed25519-verified \\
                  --repo repos/dalek-ed25519-verified \\
                  --attestation provider/out/dalek-ed25519.attestation.yaml \\
                  --trust-attestation-provider local-pacta-provider \\
                  --attestation-public-key provider/state/local-provider/provider.ed25519.pub \\
                  --transparency-receipt provider/out/dalek-ed25519.receipt.yaml \\
                  --transparency-log-public-key provider/state/local-provider/provider.ed25519.pub \\
                  --require-transparency-receipt \\
                  --action build-library
                ```
                """
            ),
            md(
                """
                ## Exercises

                - Modify a claim card to R2 and show that `build-library` is refused.
                - Explain why a denial artifact is useful for auditability.
                - Design a policy where an agent requires `both` Ed25519 and ML-DSA signatures for production deployment but allows Ed25519-only in a local lab.
                - Write a downstream Rust pseudo-code snippet that imports the generated capsule before enabling a code path.
                """
            ),
        ]
    ),
    "09_dogfood_verified_crypto.ipynb": notebook(
        [
            md(
                """
                # Lecture 9: Eat Your Own Dogfood - Verified Crypto in the Agent's Own Loop

                Every lecture so far had the agent consume EVIDENCE about a verified Ed25519 implementation while checking that evidence's signatures with OpenSSL - an unverified implementation of the very primitive the evidence is about. That is a defensible bootstrap, but it leaves an ironic gap. This lecture closes it: pacta can build a verifier binary from the PINNED, PROVEN source workspace - the exact commit the dalek certificates pin, serial backend pinned exactly as the verified extraction pins it - and route its own signature checks through it.
                """
            ),
            md(
                """
                ## Learning Objectives

                - State precisely which parts of the dogfood verifier are certificate-covered and which are its trusted base.
                - Extract a raw Ed25519 key from an OpenSSL PEM by hand (napkin) and mechanically (real).
                - Demonstrate backend dispatch and the fail-closed `--require-verified-verifier` policy.
                - Defend the hybrid post-quantum posture: one proven-classical signature plus one required-but-honest ML-DSA slot.
                """
            ),
            md(
                """
                ## What "verified" means here - the honest ledger

                The binary calls `ed25519_dalek::VerifyingKey::verify` in the pinned workspace. The certificates cover `verify_sha512`, the extraction-refactored image of that same path (the delta is the documented hash-wrapper refactor in the pinned source). Certificate-covered: field arithmetic, the group law, scalars, encoding/decoding, constructive decompression, and the four-tier acceptance criterion. Trusted base: SHA-512 (an oracle in the theorems - the proofs hold for whatever bytes it produces), roughly fifteen lines of wire glue, rustc, and the extraction pipeline. The provenance sidecar written at build time records the source commit, the backend cfg, and this exact coverage note - the dogfood claim is itself a claim card.
                """
            ),
            md(
                """
                ## Napkin: read a PEM with your eyes

                An OpenSSL Ed25519 public key PEM is a base64-wrapped DER SubjectPublicKeyInfo (RFC 8410), and for this one algorithm the DER is FIXED: twelve prefix bytes `302a300506032b6570032100`, then the raw 32-byte key. Decode one by hand:
                """
            ),
            code(
                """
                from pathlib import Path
                import base64, subprocess, sys, tempfile

                repo_root = Path.cwd()
                if not (repo_root / "src" / "pacta").exists():
                    repo_root = repo_root.parent
                sys.path.insert(0, str(repo_root / "src"))

                from pacta.signing import generate_ed25519_keypair

                tmp = Path(tempfile.mkdtemp(prefix="dogfood-lecture-"))
                generate_ed25519_keypair(tmp / "k.key", tmp / "k.pub")
                pem = (tmp / "k.pub").read_text()
                print(pem)
                body = "".join(line for line in pem.splitlines() if "-----" not in line)
                der = base64.b64decode(body)
                print("DER length:", len(der), "(should be 12 + 32 = 44)")
                print("prefix:    ", der[:12].hex(), "(the fixed Ed25519 SPKI header)")
                print("raw key:   ", der[12:].hex())
                """
            ),
            code(
                """
                # REAL: the same extraction, mechanically, with validation - and the
                # dispatch that prefers the proven-path binary when it exists.
                from pacta.dogfood import locate_verifier, pem_public_key_to_raw
                from pacta.signing import sign_payload_ed25519, verify_payload_ed25519_detailed

                raw = pem_public_key_to_raw(tmp / "k.pub")
                assert raw == der[12:]
                print("mechanical extraction matches the napkin:", raw.hex()[:16], "...")

                payload = b"the agent checks its own evidence"
                signature = sign_payload_ed25519(payload, tmp / "k.key")
                ok, error, backend = verify_payload_ed25519_detailed(payload, signature, tmp / "k.pub")
                print("valid:", ok, "| backend:", backend)
                binary = locate_verifier()
                print("dogfood binary:", binary or "not built (OpenSSL fallback in effect - a recorded downgrade)")
                """
            ),
            md(
                """
                Build the proven-path verifier once per machine (it needs a local checkout of the pinned source workspace and cargo):

                ```bash
                pacta dogfood-build --source ~/GitClone/FormalVerification/sources/curve25519-dalek-source
                pacta dogfood-status
                ```

                With the binary in place, every receipt and attestation check reports `ed25519_backend: verified-dalek-serial`, and policies can DEMAND it:

                ```bash
                pacta receipt-verify ... --require-verified-verifier   # fails closed on OpenSSL fallback
                pacta agent ... --require-verified-verifier ...
                ```
                """
            ),
            md(
                """
                ## The post-quantum line, held honestly

                The dogfood loop deliberately does NOT extend to ML-DSA. There is no formally verified ML-DSA implementation in this corpus, and pretending otherwise would poison the whole posture. The hybrid strategy is therefore asymmetric on purpose:

                - **Ed25519 (classical): proven path.** The signature everyone can check today runs on certificate-covered code.
                - **ML-DSA-65 (post-quantum): required, honest, unavailable-until-real.** The tree-head slot exists in every signed structure; `--require-signatures both` fails CLOSED on hosts without a real FIPS 204 backend; and when a real backend lands, the policy flips on without a schema change.

                A migration strategy that records "we cannot do this yet" as a deployment blocker is strictly stronger than one that ships a placeholder. Blockers get fixed; placeholders get trusted.
                """
            ),
            code(
                """
                from pacta.postquantum import detect_ml_dsa

                capability = detect_ml_dsa()
                print("ml-dsa available:", capability.available)
                print("reason:", capability.reason)
                print("slot as recorded in every STH:", capability.to_signature_slot())
                """
            ),
            md(
                """
                ## Exercises

                - Flip one byte of a signature and verify through both backends; confirm both reject and that the BACKEND that rejected is recorded.
                - The dogfood binary's trusted base includes rustc. The certificates' trusted base includes Charon/Aeneas. Draw the two trust diagrams side by side; which assumptions are shared?
                - Napkin, then real: decode a second PEM by hand; then corrupt its DER prefix and confirm `pem_public_key_to_raw` rejects it.
                - Policy design: when should an agent REFUSE to fall back to OpenSSL? Write the deployment rule and its recovery path.
                - Research checkpoint: what would a proof-carrying SHA-512 change about the coverage note in the provenance sidecar?
                """
            ),
        ]
    ),
    "08_capstone_research_program.ipynb": notebook(
        [
            md(
                """
                # Lecture 8: Capstone Research Program

                The final goal is not to memorize PACTA commands. The goal is to think like a research engineer who can build an assurance case for autonomous agents that protect funds.
                """
            ),
            md(
                """
                ## Learning Objectives

                - Design a complete assurance roadmap from R3 to R4/R5.
                - Identify proof gaps and operational gaps separately.
                - Propose theorem milestones for Ed25519, Pallas/Pasta, and wallet integration.
                - Design transparency-log monitoring and provider accountability.
                - Write a PhD-quality research proposal with measurable deliverables.
                """
            ),
            md(
                """
                ## R4, achieved - read it like an auditor

                When this course was first drafted, R4 was the roadmap. The corpus then delivered it (2026-07-06): scalar arithmetic, encoding/decoding canonicality, constructive decompression, and the four-tier signature apex, every certificate's axiom cone pinned to its documented boundary by each repository's own check script. The composition lesson stands: the hard part was never one theorem - it was composing coverage without smuggling assumptions, which is why the apex tiers are hypothesis-parametric (parser outcomes stay hypotheses) and why the boundary is enforced per certificate, in both directions.

                Your first capstone exercise is therefore no longer "design R4" but "audit R4": take the shipped claim card, list what each of the four tiers states, and name the exact residual trusted base. Then design the discharge plan:

                - byte-level specs for the wire parsers and legacy filters (turn the parse hypotheses into theorems),
                - a verified SHA-512 or a proof-carrying hash oracle (shrink the boundary),
                - signing-side coverage (nonce derivation, signer correctness),
                - the production-path mapping per fork (anza's default verify() is NOT the verified path - what would it take to cover it?).
                """
            ),
            md(
                """
                ## From R4 to R5

                R5 adds production assurance:

                - reproducible production builds,
                - compiler and build-system assurance,
                - side-channel analysis,
                - hardware/KMS/MPC integration,
                - key custody policy,
                - operational controls,
                - monitoring and incident response,
                - transparency-log monitors and consistency checks.

                R5 is where formal methods meet systems security.
                """
            ),
            md(
                """
                ## Research Milestone Template

                For each milestone, write:

                - Claim: exact theorem-boundary statement.
                - Artifact: repository, commit, file paths, theorem names.
                - Replay: how to reproduce compilation and axiom audit.
                - Exclusions: what remains out of scope.
                - Trusted base: tools, compiler, translation, provider, log, hardware.
                - Risk impact: how the milestone changes R-level classification.
                - Failure modes: what invalidates the evidence.
                """
            ),
            code(
                """
                milestone = {
                    "claim": "Scalar52 arithmetic correctness for selected serial/u64 code paths.",
                    "artifact": ["repo commit", "Lean files", "aggregate theorem name"],
                    "replay": ["portable Lean check", "#print axioms", "manifest coverage"],
                    "exclusions": ["SHA-512", "encoding", "side channels", "compiler correctness"],
                    "risk_impact": "May reduce one blocker toward R4 but does not by itself prove EdDSA.",
                }
                for key, value in milestone.items():
                    print(key, "=>", value)
                """
            ),
            md(
                """
                ## Capstone Project Options

                1. Ed25519 R4 Roadmap
                   Build a theorem dependency map from field arithmetic to full signature verification. Identify every missing certificate and propose an order of attack.

                2. Pallas/Pasta Foundation Audit
                   Determine whether shipped Pallas/Pasta certificates prove add, mul, reduce, square, invert, and aggregate field implementation. Assign R2/R3 with rationale.

                3. Transparency Provider Hardening
                   Extend the provider with external monitors, persistent checkpoints, log consistency verification between checkpoints, and real ML-DSA signing when a backend is available.

                4. Agent Policy Language
                   Design a small declarative policy language that maps claim cards and transparency receipts to allowed actions.

                5. Translation Faithfulness Research
                   Study how to connect Rust source, transpiled Lean, and compiled artifacts with a defensible trusted base.
                """
            ),
            md(
                """
                ## PhD-Level Evaluation Rubric

                A top submission should:

                - Make claims that are precise enough to be wrong.
                - Separate proof gaps from engineering gaps.
                - Include runnable reproduction steps.
                - Include negative tests and failure-mode demonstrations.
                - Use transparency receipts or equivalent accountability for third-party evidence.
                - Avoid marketing language.
                - State exactly what would invalidate the result.
                - Produce an artifact another researcher can inspect.
                """
            ),
            md(
                """
                ## Final Exercises

                - Write a two-page assurance case for using an R3 Ed25519 arithmetic capsule in a non-wallet lower-layer library.
                - Write a denial memo explaining why the same evidence must not authorize a wallet.
                - Design a monitoring protocol for PACTA transparency logs, including consistency checks and alert conditions.
                - Propose a real ML-DSA integration plan that names the backend, key format, signature format, test vectors, and failure policy.
                - Pick one theorem boundary and write the strongest claim you can defend without exaggeration.
                """
            ),
        ]
    ),
}


README = """# PACTA Curriculum Notebooks

This directory contains a zero-to-hero teaching sequence for proof-aware cryptographic tooling.

Start with `00_course_map.ipynb`, then proceed in order. The notebooks are intentionally output-free in git. Run them from the repository root or from this directory; each notebook locates the repo root and imports `pacta` from `src/`.

The course teaches:

- theorem-boundary thinking,
- claim cards and residual risk,
- Lean replay and axiom audit concepts,
- proof hygiene,
- third-party proof-check provider trust,
- RFC 9162-style Merkle transparency logs,
- receipt-gated agent consequences (including the R4 wallet gate, now reachable),
- split-view defense: STH pinning, consistency enforcement, freshness, monitoring,
- dogfood verified cryptography and the honest hybrid post-quantum posture,
- research roadmaps from R4 evidence toward R5 assurance.

This curriculum is not financial advice, not a trading bot, and not a wallet-building guide. It is a training path for engineers and researchers who need to evaluate formal-verification-enhanced cryptographic tooling without overclaiming.
"""


def main() -> None:
    NOTEBOOK_DIR.mkdir(parents=True, exist_ok=True)
    for name, data in COURSE.items():
        path = NOTEBOOK_DIR / name
        path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    (NOTEBOOK_DIR / "README.md").write_text(README, encoding="utf-8")


if __name__ == "__main__":
    main()
