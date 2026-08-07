# The plain-language explainer

*For readers with no Lean background and only a little cryptography. This
page translates two papers: the published one about the Lean Transparency
Log (currently under journal review), and a second one, in preparation,
about what it took to make any of it believable.*

---

## Start here: what is this whole project?

Software that handles digital signatures — the mathematics that proves an
email, a payment, or an update really came from who it claims — is some of
the most consequential code in the world. It is usually *tested*: you run
it on many examples and see that it behaves. Testing is good, but it can
only ever say "we didn't find a bug," never "there is no bug."

There is a stronger option. You can *prove* a program correct, the way
mathematicians prove theorems — covering **every possible input at once**,
not just the ones you tried. Doing this by hand would be error-prone, so
the proof itself is written for a machine: a small, famously pedantic
referee program (ours is called **Lean**) that checks every logical step
and refuses anything that doesn't follow. You don't have to understand the
proof. You only have to know that the referee — a few thousand lines of
code that experts worldwide have stared at for years — accepted it.

This project did that for real signature-checking code: four independent
implementations of **Ed25519** (today's workhorse signature scheme) and one
implementation of **SLH-DSA** (a new scheme designed to survive quantum
computers). Not toy versions — the actual deployed code, mechanically
translated into the referee's language and proven correct there.

## The uncomfortable question, and paper 1's answer

So far so good. But now *you* come along, and we tell you: "this code is
formally verified." Why should you believe us?

You weren't there. You didn't watch the referee accept anything. Maybe we
proved something *else* than we claim. Maybe we proved it about an *older
version*. Maybe we're just lying. "Trust me, it's proven" is exactly the
kind of sentence this project refuses to end on.

**Paper 1 — "the log paper" — is about the machine we built so you don't
have to trust us.** Think of a notary's ledger with two unusual properties:

1. **Pages can be added, never changed or torn out.** Each page (we call it
   a *leaf*) records one claim: "this exact version of this software was
   checked, here is exactly what was proven, and here is exactly what was
   assumed." The exact version matters — the page names a fingerprint of
   the code, so it can't quietly refer to something else.
2. **The whole ledger folds up into one short fingerprint** (via a
   structure called a Merkle tree — the same trick behind blockchains and
   Certificate Transparency, the system browsers already use to police
   HTTPS certificates). We sign that fingerprint. If we ever altered an old
   page, the fingerprint would change, the old signed fingerprints would
   stop matching, and anyone holding yesterday's copy could prove we
   cheated.

The ledger is public — a website (ltl.zkdefi.org) and an ordinary git
repository you can clone. It ships a small program, `verify.py`, that
re-checks the entire ledger on **your** machine: every page's fingerprint,
every historical signed fingerprint, every receipt. One command, standard
tools, no trust in us anywhere in the loop.

And here is the part that makes paper 1 a *paper* rather than a product
page: **the mathematics of the ledger itself is proven, too** — with the
same referee, and (this is the pleasingly recursive part) *those proofs are
recorded as a page inside the very ledger they are about*. The paper works
out precisely what such a log can and cannot promise: it cannot *prevent* a
dishonest operator from misbehaving, but it makes every misbehavior
**provable by the victim** — cheating produces cryptographic evidence
usable against us. "Honest, or caught" is the actual guarantee, and the
paper is precise about it.

One note if you read paper 1 itself: it is frozen while under review, and
describes the ledger as of July 2026 (13 pages in the ledger, one signature
scheme). The ledger has since grown — 19 pages, including the first
post-quantum entry, and every new fingerprint now carries two signatures.
Nothing the paper describes was altered; its snapshot sits *unchanged
inside* today's ledger, which is exactly what "pages are never rewritten"
means. The website's paper section explains this in detail.

## "The button" — the jargon you will meet everywhere here

Every verified repository ships a script, `check.sh`. We call it **the
button**. It is not on any website; you clone the repository and run it in
a terminal. It rebuilds every proof from nothing and asks the referee, for
every theorem: *do you accept this — and what exactly does it rest on?*
About thirty minutes later it prints **ALL GREEN**, or it fails loudly.
Green means: *the proofs re-checked on your machine, resting on exactly the
assumptions listed in the repository's own trust document — nothing more,
nothing less.*

Why make jargon of something so simple? Because the button turned out to be
the most dangerous component in the whole project. Which brings us to
paper 2.

## Paper 2: the confession

Here is the asymmetry that paper 2 exists to report. Proving the eleven
theorems about the quantum-resistant verifier took **two days**, and no
reviewer ever found a flaw in any theorem — not one, in nine rounds of
hostile review. Making the *green light believable* took **months**, and
the reviewers found problems constantly. Fifty-three of them, all written
down. Every single one was in the machinery *around* the proofs, never in
the mathematics.

The emblem of the whole paper: a reviewer once sabotaged a single helper
file and the button printed ALL GREEN over deliberately destroyed proofs —
in **3.6 seconds** instead of thirty minutes. The referee was never
consulted. The light just... turned on. Nothing was wrong with any proof;
everything was wrong with the *evidence*.

Paper 2 says: verification is **two acts**. Act one is the mathematics —
the referee accepting your theorems. Act two is everything that binds the
referee's verdict to the public claim: the button, the scripts, the
documents, the ledger entry — all ordinary, fallible software. The
literature celebrates act one. Act two is where all our defects lived, and
nobody writes it down. So we did: what the failures look like (they fall
into a small number of recurring patterns — lights that turn on when a
check *couldn't run*, checkers nothing checks, counting by name instead of
by substance, reports that outlive their truth), what rules kill each
pattern, and the receipts — every defect dated, in the reviewers' own
words, in a public register. A paper of negative results, on purpose:
the expensive lessons are the ones worth publishing.

## The one sentence to take away

**Act one: machines checked our mathematics. Act two: we built a public,
append-only paper trail so you can check *us* — and paper 2 is the honest
bill for act two.** If you remember only that, you've understood both
papers.

## If you have fifteen minutes

```
git clone https://github.com/saymrwulf/lean-transparency-log
cd lean-transparency-log
python3 verify.py --all
```

If that prints `RESULT: OK [full]`, you have personally re-derived every
fingerprint, signature, and receipt in the ledger — and you never once had
to trust this page.
