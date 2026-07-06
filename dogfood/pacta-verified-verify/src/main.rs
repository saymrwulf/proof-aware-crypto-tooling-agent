//! pacta's dogfood Ed25519 verifier.
//!
//! This binary is built against the PINNED, PROVEN source workspace
//! (saymrwulf/curve25519-dalek-source at the commit named in the build
//! provenance) with the serial backend pinned - the exact code path whose
//! correctness certificates pacta consumes. When pacta checks a provider
//! signature or a signed tree head through this binary, the agent is
//! eating its own dogfood: the arithmetic under the verification is
//! certificate-covered (field, group law, scalars, decompression, and the
//! four-tier signature apex), and the residual trusted base is exactly the
//! theorems' documented boundary (SHA-512 as an oracle, the wire glue).
//!
//! Usage: pacta-verified-verify <pubkey-hex-32B> <sig-hex-64B> <payload-file>
//! Exit 0 = signature valid; exit 1 = invalid; exit 2 = usage/format error.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::process::ExitCode;

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex".into());
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("usage: pacta-verified-verify <pubkey-hex> <sig-hex> <payload-file>");
        return ExitCode::from(2);
    }
    let pk_bytes = match hex_decode(&args[1]) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            eprintln!("error: public key must be 32 bytes of hex");
            return ExitCode::from(2);
        }
    };
    let sig_bytes = match hex_decode(&args[2]) {
        Ok(b) if b.len() == 64 => b,
        _ => {
            eprintln!("error: signature must be 64 bytes of hex");
            return ExitCode::from(2);
        }
    };
    let payload = match std::fs::read(&args[3]) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot read payload: {e}");
            return ExitCode::from(2);
        }
    };
    let mut pk_array = [0u8; 32];
    pk_array.copy_from_slice(&pk_bytes);
    let verifying_key = match VerifyingKey::from_bytes(&pk_array) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("error: invalid public key: {e}");
            return ExitCode::from(2);
        }
    };
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_array);
    match verifying_key.verify(&payload, &signature) {
        Ok(()) => {
            println!("OK");
            ExitCode::SUCCESS
        }
        Err(_) => {
            println!("INVALID");
            ExitCode::from(1)
        }
    }
}
