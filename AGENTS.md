# AGENTS.md

Guidance for future Codex runs in this repository:

- Do not add Charon or Aeneas transpilation flows.
- Do not regenerate Lean from Rust. Treat shipped Lean files in verified repos as the artifact.
- Do not claim end-to-end verification unless theorem coverage actually exists.
- Keep macOS and Apple Silicon portability. Do not rely on GNU `timeout`, `free`, `taskset`, Docker, Nix, or x86_64 assumptions.
- Prefer explicit theorem-boundary language over marketing language.
- Update tests with every behavior change.
- Do not silently lower risk ratings. A lower score must explain the failed or missing evidence.
- Do not hide proof failures behind warnings.
- Keep claim cards machine-readable and reports explicit about proven claims, preconditions, exclusions, trusted base, and residual risk.
