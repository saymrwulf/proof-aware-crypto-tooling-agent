"""Quorum boundary: divergence taxonomy, unanimity, edge flags.

Unit tests use fake verifier binaries (tiny shell scripts with fixed
verdicts) so the taxonomy logic is exercised without needing cargo or the
pinned sources. An integration test runs the REAL built quorum when the
binaries are present, and skips cleanly otherwise.
"""

import os
import stat
from pathlib import Path

import pytest

from pacta.quorum import (
    QuorumVerifier,
    SMALL_ORDER_ENCODINGS,
    binary_path,
    load_quorum,
    semantic_edge_flags,
)


def _fake_member(path: Path, verdict: str) -> None:
    """verdict in {accept, reject, error}."""
    code = {"accept": 0, "reject": 1, "error": 2}[verdict]
    out = {"accept": "OK", "reject": "INVALID", "error": "boom"}[verdict]
    path.write_text(f"#!/bin/sh\necho {out}\nexit {code}\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def _quorum(tmp_path: Path, verdicts: dict[str, str]) -> QuorumVerifier:
    members = {}
    for name, verdict in verdicts.items():
        binary = tmp_path / f"pacta-verify-{name}"
        _fake_member(binary, verdict)
        members[name] = binary
    return QuorumVerifier(members, min_members=2)


def test_unanimous_accept(tmp_path):
    q = _quorum(tmp_path, {"a": "accept", "b": "accept", "c": "accept"})
    r = q.verify(b"payload", b"\x01" * 64, b"\x02" * 32)
    assert r.accepted
    assert r.classification == "unanimous-accept"
    assert r.incident is None


def test_unanimous_reject(tmp_path):
    q = _quorum(tmp_path, {"a": "reject", "b": "reject"})
    r = q.verify(b"payload", b"\x01" * 64, b"\x02" * 32)
    assert not r.accepted
    assert r.classification == "unanimous-reject"


def test_divergence_on_ordinary_input_is_tamper(tmp_path):
    # Members disagree with no documented edge -> unexplained/tamper.
    q = _quorum(tmp_path, {"a": "accept", "b": "reject"})
    r = q.verify(b"payload", b"\x01" * 64, b"\x02" * 32)
    assert not r.accepted
    assert r.classification == "unexplained"
    assert r.incident["severity"] == "tamper"


def test_divergence_on_small_order_R_is_semantic_edge(tmp_path):
    # Members disagree AND R is on the legacy exclusion list -> note, not tamper.
    small_order_R = sorted(SMALL_ORDER_ENCODINGS)[0]
    signature = small_order_R + b"\x00" * 32
    q = _quorum(tmp_path, {"dalek": "accept", "anza": "reject"})
    r = q.verify(b"payload", signature, b"\x02" * 32)
    assert not r.accepted
    assert r.classification == "semantic-edge"
    assert r.incident["severity"] == "note"
    assert any("small-order-R" in f for f in r.edge_flags)


def test_member_error_forces_unexplained(tmp_path):
    # A member that errors (exit 2) can never be a benign semantic edge.
    small_order_R = sorted(SMALL_ORDER_ENCODINGS)[0]
    signature = small_order_R + b"\x00" * 32
    q = _quorum(tmp_path, {"a": "accept", "b": "error"})
    r = q.verify(b"payload", signature, b"\x02" * 32)
    assert r.classification == "unexplained"
    assert r.incident["severity"] == "tamper"


def test_edge_flags_detect_classes():
    zero_key = b"\x00" * 32
    assert "zero-public-key" in semantic_edge_flags(zero_key, b"\x00" * 64)
    # non-canonical s: all 0xff is well above the group order
    flags = semantic_edge_flags(b"\x02" * 32, b"\x01" * 32 + b"\xff" * 32)
    assert any("non-canonical-s" in f for f in flags)


def test_small_order_list_is_conservative():
    # The fail-safe contract: every listed encoding must be a certain
    # low-order y-value (0, 1, or -1), reduced or non-reduced, sign bit
    # either way. No order-8 or unverifiable entries may sneak in, because a
    # bogus entry would down-grade a real tamper to a note.
    p = 2**255 - 19
    allowed_y = {0, 1, p - 1, p, p + 1}
    for enc in SMALL_ORDER_ENCODINGS:
        y = int.from_bytes(enc, "little") & ((1 << 255) - 1)  # strip sign bit
        assert y in allowed_y, f"non-low-order encoding in list: {enc.hex()}"


def test_quorum_requires_min_members(tmp_path):
    with pytest.raises(ValueError):
        _quorum(tmp_path, {"only": "accept"})


def test_missing_binary_rejected(tmp_path):
    with pytest.raises(ValueError):
        QuorumVerifier({"a": tmp_path / "nope", "b": tmp_path / "nope2"}, min_members=2)


def test_real_quorum_agrees_on_valid_and_invalid(tmp_path):
    if not all(binary_path(b).exists() for b in ("dalek", "anza")):
        pytest.skip("real quorum binaries not built (run `pacta wallet build-quorum`)")
    from pacta.dogfood import locate_verifier, pem_public_key_to_raw, sign_payload_dogfood
    from pacta.signing import generate_ed25519_keypair

    verifier = locate_verifier()
    if verifier is None:
        pytest.skip("dogfood signer not built")
    key = tmp_path / "k.pem"
    pub = tmp_path / "k.pub"
    generate_ed25519_keypair(key, pub)
    payload = b"real quorum integration payload"
    signature = sign_payload_dogfood(payload, key, verifier)
    public_key = pem_public_key_to_raw(pub)
    q = load_quorum(min_members=2)
    good = q.verify(payload, signature, public_key)
    assert good.accepted and good.classification == "unanimous-accept"
    bad = q.verify(payload, bytes([signature[0] ^ 0xFF]) + signature[1:], public_key)
    assert not bad.accepted and bad.classification == "unanimous-reject"
