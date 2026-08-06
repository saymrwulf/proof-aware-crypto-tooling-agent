"""SLH-DSA signing path: deterministic, parameter-locked, two-verifier checked.

Every test uses THROWAWAY keys generated into tmp_path. No test touches the
provider state directory or any long-lived key.
"""
from __future__ import annotations

import base64
import json


def _keypair(tmp_path):
    from pacta.slhdsa import generate_slhdsa_keypair
    priv, pub = tmp_path / "t.key", tmp_path / "t.pub"
    generate_slhdsa_keypair(priv, pub)
    return priv, pub


def test_keygen_shape_and_permissions(tmp_path):
    priv, pub = _keypair(tmp_path)
    assert priv.exists() and pub.exists()
    assert (priv.stat().st_mode & 0o777) == 0o600


def test_deterministic_signing_reproduces_bytes(tmp_path):
    """Operator decision 2026-08-06: same payload + key => identical bytes.
    This is the property the Ed25519 reproducibility check relies on, and the
    reason the deterministic variant was chosen over the FIPS 205 default."""
    from pacta.slhdsa import sign_payload_slhdsa
    priv, _pub = _keypair(tmp_path)
    payload = b"the same head payload"
    assert sign_payload_slhdsa(payload, priv) == sign_payload_slhdsa(payload, priv)


def test_sign_verify_roundtrip_both_verifiers(tmp_path):
    from pacta.slhdsa import (locate_proven_verifier, sign_payload_slhdsa,
                              verify_payload_slhdsa, verify_payload_slhdsa_proven)
    priv, pub = _keypair(tmp_path)
    payload = b"a transparency log head payload"
    sig = sign_payload_slhdsa(payload, priv)
    ok, err = verify_payload_slhdsa(payload, sig, pub)
    assert ok, err
    if locate_proven_verifier() is None:
        import pytest
        pytest.skip("pacta-verify-slhdsa not built on this host")
    ok, err = verify_payload_slhdsa_proven(payload, sig, pub)
    assert ok, f"proven-source verifier disagrees with OpenSSL: {err}"


def test_corruption_rejected_by_both(tmp_path):
    from pacta.slhdsa import (locate_proven_verifier, sign_payload_slhdsa,
                              verify_payload_slhdsa, verify_payload_slhdsa_proven)
    priv, pub = _keypair(tmp_path)
    payload = b"payload"
    raw = bytearray(base64.b64decode(sign_payload_slhdsa(payload, priv)))
    raw[0] ^= 1
    bad = base64.b64encode(bytes(raw)).decode()
    ok, _ = verify_payload_slhdsa(payload, bad, pub)
    assert not ok
    if locate_proven_verifier() is not None:
        ok, _ = verify_payload_slhdsa_proven(payload, bad, pub)
        assert not ok


def test_parameter_set_lock_refuses_foreign_key(tmp_path):
    """An Ed25519 key must be refused outright — a signature under any other
    algorithm would look like dogfood while sitting outside every proof."""
    import pytest
    from pacta.signing import generate_ed25519_keypair
    from pacta.slhdsa import SlhDsaError, sign_payload_slhdsa
    priv, pub = tmp_path / "ed.key", tmp_path / "ed.pub"
    generate_ed25519_keypair(priv, pub)
    with pytest.raises(SlhDsaError):
        sign_payload_slhdsa(b"x", priv)


def test_head_carries_separate_slh_dsa_block(tmp_path):
    """make_signed_tree_head with an SLH-DSA key: both signatures verify, the
    ml_dsa slot is UNTOUCHED, and without a key the slot degrades honestly."""
    from pacta.signing import generate_ed25519_keypair, verify_payload_ed25519_detailed
    from pacta.slhdsa import verify_payload_slhdsa
    from pacta.transparency import make_signed_tree_head, signed_tree_head_payload

    ed_priv, ed_pub = tmp_path / "ed.key", tmp_path / "ed.pub"
    generate_ed25519_keypair(ed_priv, ed_pub)
    slh_priv, slh_pub = _keypair(tmp_path)

    sth = make_signed_tree_head("00" * 32, 19, "11" * 32, "2026-08-06T00:00:00Z",
                                ed_priv, ed_pub,
                                slhdsa_private_key_path=slh_priv,
                                slhdsa_public_key_path=slh_pub)
    payload = signed_tree_head_payload(sth)

    ed = sth["signatures"]["ed25519"]
    ok, err, _backend = verify_payload_ed25519_detailed(payload, ed["signature_base64"], ed_pub)
    assert ok, err

    slh = sth["signatures"]["slh_dsa"]
    assert slh["status"] == "signed"
    assert slh["parameter_set"] == "SLH-DSA-SHA2-128s"
    assert slh["mode"] == "deterministic"
    ok, err = verify_payload_slhdsa(payload, slh["signature_base64"], slh_pub)
    assert ok, err

    # ml_dsa stays exactly the honest disclosure it always was
    assert sth["signatures"]["ml_dsa"]["status"] in {"not_configured", "unavailable"}
    assert "signature_base64" not in sth["signatures"]["ml_dsa"]

    # additive: no key => honest not-configured slot, never an error
    bare = make_signed_tree_head("00" * 32, 19, "11" * 32, "2026-08-06T00:00:00Z",
                                 ed_priv, ed_pub)
    assert bare["signatures"]["slh_dsa"]["status"] == "not_configured"

    # and the payload is unchanged by the slh_dsa presence: signatures are
    # outside the signed bytes for BOTH algorithms
    assert signed_tree_head_payload(bare) == payload


def test_block_is_json_serialisable(tmp_path):
    from pacta.slhdsa import slh_dsa_signature_block
    priv, pub = _keypair(tmp_path)
    block = slh_dsa_signature_block(b"payload", priv, pub)
    json.dumps(block)
    assert set(block) >= {"scheme", "standard", "parameter_set", "mode", "status",
                          "payload_digest_sha256", "signature_base64",
                          "public_key_fingerprint_sha256"}
