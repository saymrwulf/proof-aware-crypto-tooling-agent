import os
import stat
import subprocess

from pacta.dogfood import BACKEND_VERIFIED, locate_verifier, pem_public_key_to_raw
from pacta.signing import generate_ed25519_keypair, sign_payload_ed25519, verify_payload_ed25519_detailed


def test_pem_spki_to_raw_roundtrip(tmp_path):
    private_key = tmp_path / "k.key"
    public_key = tmp_path / "k.pub"
    generate_ed25519_keypair(private_key, public_key)
    raw = pem_public_key_to_raw(public_key)
    assert len(raw) == 32
    # cross-check against openssl's own raw dump
    dumped = subprocess.run(
        ["openssl", "pkey", "-pubin", "-in", str(public_key), "-outform", "DER"],
        capture_output=True, check=True,
    ).stdout
    assert dumped.endswith(raw)


def test_pem_rejects_non_ed25519(tmp_path):
    bogus = tmp_path / "bogus.pub"
    bogus.write_text("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n")
    import pytest

    with pytest.raises(ValueError):
        pem_public_key_to_raw(bogus)


def test_dispatch_prefers_dogfood_binary_and_records_backend(tmp_path, monkeypatch):
    # a fake verifier that accepts everything: proves dispatch + backend label
    fake = tmp_path / "fake-verify"
    fake.write_text("#!/bin/sh\necho OK\nexit 0\n")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    private_key = tmp_path / "k.key"
    public_key = tmp_path / "k.pub"
    generate_ed25519_keypair(private_key, public_key)
    payload = b"dogfood dispatch test"
    signature = sign_payload_ed25519(payload, private_key)
    monkeypatch.setenv("PACTA_DOGFOOD_VERIFIER", str(fake))
    ok, error, backend = verify_payload_ed25519_detailed(payload, signature, public_key)
    assert ok and backend == BACKEND_VERIFIED
    monkeypatch.setenv("PACTA_DOGFOOD_VERIFIER", str(tmp_path / "missing"))
    assert locate_verifier() is None
    ok, error, backend = verify_payload_ed25519_detailed(payload, signature, public_key)
    assert ok and backend == "openssl"


def test_real_dogfood_binary_if_built(tmp_path):
    import pytest

    binary = locate_verifier()
    if binary is None or "fake" in str(binary):
        pytest.skip("dogfood verifier not built on this host")
    private_key = tmp_path / "k.key"
    public_key = tmp_path / "k.pub"
    generate_ed25519_keypair(private_key, public_key)
    payload = b"the proven path verifies this"
    signature = sign_payload_ed25519(payload, private_key)
    ok, error, backend = verify_payload_ed25519_detailed(payload, signature, public_key)
    assert ok and backend == BACKEND_VERIFIED
    # flip one payload byte: the proven path must reject
    ok, error, backend = verify_payload_ed25519_detailed(payload + b"x", signature, public_key)
    assert not ok and backend == BACKEND_VERIFIED
