//! warden quorum member: SLH-DSA-SHA2-128s, the Lean-proven verify path.
//!
//! Built against a copy of the PINNED proven source (`fips205-source` at the
//! commit named in the build provenance sidecar) plus `expose-mono.patch`,
//! which adds a visibility keyword and an argument-assembly function and
//! changes no existing line's semantics.
//!
//! The function this calls, `slh_verify_128s`, is the extraction root the
//! eleven certificates cover, apex `fips205.slh_verify_128s_accepts_iff`.
//! Verify-only on purpose: quorum members judge, they never sign.
//!
//! TWO THINGS THIS BINARY DOES THAT NO CERTIFICATE COVERS, stated here because
//! a reader of the output cannot see them:
//!
//!   * It assembles M'. FIPS 205 hashes M' = toByte(0,1) ‖ toByte(|ctx|,1) ‖
//!     ctx ‖ M, and Algorithm 20's input is already M'. Everything above the
//!     extraction root -- including that leading domain-separator byte, the one
//!     thing distinguishing the pure variant from prehash -- is outside every
//!     proof (TRUSTED-BASE item 10). This binary implements the PURE variant
//!     with EMPTY context, i.e. M' = 0x00 ‖ 0x00 ‖ payload, and refuses to
//!     guess at anything else.
//!   * It parses hex and reads a file.
//!
//! Usage: <pubkey-hex-32B> <sig-hex-7856B> <payload-file>
//! stdout OK / INVALID; exit 0 = accept, 1 = reject, 2 = input error.

use std::process::ExitCode;

const SIG_LEN: usize = 7856;
const PK_LEN: usize = 32;

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
        eprintln!("usage: {} <pubkey-hex-32B> <sig-hex-7856B> <payload-file>", args[0]);
        return ExitCode::from(2);
    }

    let pk_bytes = match hex_decode(&args[1]) {
        Ok(b) if b.len() == PK_LEN => b,
        Ok(b) => {
            eprintln!("error: public key must be {PK_LEN} bytes, got {}", b.len());
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("error: public key hex: {e}");
            return ExitCode::from(2);
        }
    };
    let sig_bytes = match hex_decode(&args[2]) {
        Ok(b) if b.len() == SIG_LEN => b,
        Ok(b) => {
            // Size is part of the parameter set. A 7856-byte signature is
            // SLH-DSA-SHA2-128s; anything else is a DIFFERENT parameter set and
            // outside every certificate this binary exists to exercise. Refuse
            // rather than attempt it.
            eprintln!("error: signature must be {SIG_LEN} bytes (SLH-DSA-SHA2-128s), got {}", b.len());
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("error: signature hex: {e}");
            return ExitCode::from(2);
        }
    };
    let payload = match std::fs::read(&args[3]) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot read payload file {}: {e}", args[3]);
            return ExitCode::from(2);
        }
    };

    // M' for the PURE variant with empty context: two length/domain bytes then
    // the message. Built here, not proven anywhere.
    let mut mprime = Vec::with_capacity(payload.len() + 2);
    mprime.push(0u8); // domain separator: 0 = pure, 1 = prehash
    mprime.push(0u8); // |ctx| = 0
    mprime.extend_from_slice(&payload);

    let mut sig_arr = [0u8; SIG_LEN];
    sig_arr.copy_from_slice(&sig_bytes);
    let mut pk_arr = [0u8; PK_LEN];
    pk_arr.copy_from_slice(&pk_bytes);

    if fips205::verify_mono::verify_mono_bytes(&mprime, &sig_arr, &pk_arr) {
        println!("OK");
        ExitCode::from(0)
    } else {
        println!("INVALID");
        ExitCode::from(1)
    }
}
