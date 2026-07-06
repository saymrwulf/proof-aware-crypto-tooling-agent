//! warden quorum member: betrusted curve25519-dalek fork verify path.
//!
//! Built against the PINNED proven source workspace (the commit named in
//! the build provenance sidecar), serial backend pinned - the exact code
//! path whose correctness certificates the transparency log carries for
//! this fork. Verify-only on purpose: quorum members judge, they never
//! sign.
//!
//! Usage: <pubkey-hex-32B> <sig-hex-64B> <payload-file>
//! stdout OK / INVALID; exit 0 = accept, 1 = reject, 2 = input error.

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
        eprintln!("usage: {} <pubkey-hex> <sig-hex> <payload-file>", args[0]);
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
        Err(_) => {
            // A key that fails point decompression is a REJECT verdict, not
            // an input error: quorum members must all judge the same bytes.
            println!("INVALID");
            return ExitCode::from(1);
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
