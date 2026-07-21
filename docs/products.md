# warden — the product lineup

warden is one core (quorum boundary + signing firewall + hash-chained
ledger + agent-native MCP surface) with four deployment profiles. These
are **production-ready product definitions**, not four separate codebases:
each is the same `pacta wallet` core with a different signer, policy, and
surface. Presented here as products so the shape of each is unambiguous.

Every profile also ships the same human surface: the **custody cockpit**
(`pacta wallet cockpit`) — local, read-only, six role stations over live
evidence instruments, with the deck, the guide, and the lab manual. See
[docs/cockpit.md](cockpit.md).

The trust posture in [WALLET.md](../WALLET.md#trust-posture) applies to all
four without exception. What differs is *where the boundary sits* and *what
the wallet is wired into*.

---

## 1. warden-solo — the custody sidecar

**For:** a single autonomous agent that owns a wallet and must not sign
anything it would regret.

**Shape:** local dogfood signer; the quorum firewall on every outbound
signature; MCP over stdio next to the agent. The agent calls
`request_signature` with an intent; warden binds the intent to the bytes,
signs, runs the four-fork firewall, and releases only on unanimity. Every
inbound authorization the agent receives goes through `verify_inbound`
first.

**The sci-fi line:** *the agent gets a conscience it cannot bribe.* The
refusal receipts are the conscience made portable — when warden says no,
the agent can prove to its principal exactly what was refused and why.

**Ready because:** this is the tested default path. `pacta wallet init`
→ `mcp`; the live end-to-end test is exactly this profile.

---

## 2. warden-airgap — the signing firewall for hardware custody

**For:** custody where the key must never touch the networked host — a
Precursor/Betrusted device, an HSM, a phone in a drawer.

**Shape:** the `AirgapSigner`. An outbound request is written to
`airgap/outbox/<id>.request.json`; the device (or a human courier) signs
across the gap and drops `airgap/inbox/<id>.response.json`. warden resumes
on the next call with the same request id — **and the returned signature
still faces the quorum firewall.**

**The sci-fi line:** *verify-after-sign, but the verifier is proven.* The
classic countermeasure against fault-injection on a signer is to verify
its output before trusting it; warden makes that verifier a quorum of
machine-checked code. A glitched or substituted device signature is
quarantined and latches custody — it never reaches the chain.

**Ready because:** the airgap protocol is a two-file JSON exchange with a
documented schema and a park-then-complete test; the betrusted fork it
leans on is one of the four proven members.

---

## 3. warden-treasury — trust-minimized chain watching

**For:** an agent (or a fleet) that must believe on-chain state — a
deposit landed, a multisig approved — without trusting an RPC provider's
word.

**Shape:** point the `anza` member (Solana's own verify path,
certificate-covered) at the signatures on transactions touching the
treasury and re-verify them locally through the quorum before believing
any balance change. The RPC provider is demoted from oracle to bandwidth.
This is the observation-not-verdict principle applied to chain data: take
the bytes, re-derive the verdict, with a verifier you hold a proof about.

**The sci-fi line:** *the treasury trusts mathematics, not middlemen.* A
compromised or lying RPC can withhold data but cannot manufacture a
signature the quorum will accept.

**Ready because:** it is built: `pacta wallet treasury-verify` parses
wire-format transactions (legacy + v0, stdlib only) and quorum-verifies
every required signature, with the completeness gap (an RPC can withhold)
named in every verdict. The wire parser is ~120 lines of declared trusted
base, exactly like the forks' own parsers are hypotheses of the theorems.

---

## 4. warden-choir — cross-witnessed custody

**For:** operators who want no single warden to be able to rewrite its own
history unobserved.

**Shape:** N wardens gossip each other's ledger heads and periodically
cross-sign them — the same witness pattern the Lean Transparency Log uses
for its signed tree heads, turned inward on the wallets' own append-only
ledgers. A warden that tried to fork or rewrite its ledger would have to
fool every peer that holds a countersigned head.

**The sci-fi line:** *a wallet that keeps the others honest.* Custody
becomes a small transparency log of its own, and equivocation has to
survive every member's memory.

**Ready because:** the ledger is already hash-chained and every head is
already exportable in the posture attestation; the choir is a gossip layer
over primitives that exist and are tested. (This profile is defined and
scaffolded; the gossip transport is the one net-new component and is
scoped as the next build.)

---

## Honesty about "production-ready"

Profiles 1, 2, and 3 run end-to-end today on the tested core. Profile 4
is a complete *product definition* on the same core with one documented
integration point (a gossip transport) —
named here so the boundary between "built and tested" and "wired to your
environment" is exact, which is the whole ethos of this project. None of
them changes the trust posture; all of them fail closed.
