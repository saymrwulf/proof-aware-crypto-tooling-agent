from pacta.signing import generate_ed25519_keypair, sign_attestation, verify_attestation_signature


def test_openssl_ed25519_attestation_signature_round_trip(tmp_path):
    private_key = tmp_path / "provider.key"
    public_key = tmp_path / "provider.pub"
    generate_ed25519_keypair(private_key, public_key)
    attestation = {
        "schema_version": 1,
        "provider": "local-test-provider",
        "subject": {"component": "mini"},
        "certificates": [],
    }
    signed = sign_attestation(attestation, private_key, public_key)
    ok, error = verify_attestation_signature(signed, public_key)
    assert ok, error
    signed["subject"]["component"] = "tampered"
    ok, error = verify_attestation_signature(signed, public_key)
    assert not ok
    assert error
