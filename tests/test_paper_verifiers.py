"""Historical regression pin from the archived v0.2 system report
(hosted at /paper/v0.2), which cited these exact differential-testing
counts (164,479 inclusion; 164,224 consistency) for its recursive forms
against the deployed iterative RFC 9162 verifiers over these families.
The CURRENT paper makes no extensional-equality claim: it cites the
accumulator corpus's fidelity harness instead (230,271 / 230,016 honest
families, 73,573 lied-size cases with 3,867 divergences, every one
accepted only by the deployed verifier). This test remains as a pinned
regression boundary for the pacta-internal recursive forms.
"""

import hashlib

from pacta.transparency import (
    consistency_proof,
    inclusion_proof,
    merkle_root,
    verify_consistency,
    verify_inclusion,
)

NMAX = 256


def _h(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _hleaf(d: bytes) -> bytes:
    return _h(b"\x00" + d)


def _hnode(x: bytes, y: bytes) -> bytes:
    return _h(b"\x01" + x + y)


def _k_below(n: int) -> int:
    k = 1
    while 2 * k < n:
        k *= 2
    return k


# --- the paper's recursive inclusion verifier (App. B) ---------------------
def _root(v, m, n, path):
    if n == 1:
        if path:
            raise ValueError
        return v
    if not path:
        raise ValueError
    *rest, s = path
    k = _k_below(n)
    return _hnode(_root(v, m, k, rest), s) if m < k else _hnode(s, _root(v, m - k, n - k, rest))


def _paper_incl(d, m, n, path, root):
    if not (0 <= m < n):
        return False
    try:
        return _root(_hleaf(d), m, n, path) == root
    except ValueError:
        return False


# --- the paper's recursive consistency verifier (§5.3, ConsRec) ------------
def _consrec(m, n, P, b, r0):
    if m == n:
        if b:
            if P:
                raise ValueError
            return (r0, r0)
        if len(P) != 1:
            raise ValueError
        return (P[0], P[0])
    if not P:
        raise ValueError
    *rest, s = P
    k = _k_below(n)
    if m <= k:
        x, y = _consrec(m, k, rest, b, r0)
        return (x, _hnode(y, s))
    xr, yr = _consrec(m - k, n - k, rest, False, r0)
    return (_hnode(s, xr), _hnode(s, yr))


def _paper_cons(m, n, r0, r1, P):
    if m == 0:
        return True
    if m > n:
        return False
    try:
        x, y = _consrec(m, n, P, True, r0)
    except ValueError:
        return False
    return x == r0 and y == r1


def test_recursive_inclusion_equals_deployed_exhaustive():
    total = 0
    for n in range(1, NMAX + 1):
        data = [bytes([i % 251]) + bytes([(i * 5) % 256]) * (i % 3) for i in range(n)]
        root = merkle_root(data)
        for m in range(n):
            P = inclusion_proof(data, m)
            cases = [
                (data[m], m, n, P, root),
                (data[m] + b"!", m, n, P, root),
                (data[m], (m + 1) % n, n, P, root),
                (data[m], m, n, P, _h(b"q")),
            ]
            if P:
                cases.append((data[m], m, n, P[:-1], root))
            for d2, m2, n2, P2, r2 in cases:
                total += 1
                assert verify_inclusion(d2, m2, n2, P2, r2) == _paper_incl(d2, m2, n2, P2, r2), (n, m)
            assert verify_inclusion(data[m], m, n, P, root)
            assert _paper_incl(data[m], m, n, P, root)
    assert total == 164_479, total  # the count cited in the paper


def test_recursive_consistency_equals_deployed_exhaustive():
    total = 0
    for n in range(1, NMAX + 1):
        data = [bytes([i % 251]) + bytes([(i * 7) % 256]) * (i % 4) for i in range(n)]
        r1 = merkle_root(data)
        for m in range(1, n + 1):
            P = consistency_proof(data, m)
            r0 = merkle_root(data[:m])
            cases = [
                (m, n, r0, r1, P),
                (m, n, _h(b"x"), r1, P),
                (m, n, r0, _h(b"y"), P),
                (m, n, r0, r1, P + [_h(b"z")]),
            ]
            if P:
                cases.append((m, n, r0, r1, P[:-1]))
            for mm, nn, a, bb, pp in cases:
                total += 1
                assert verify_consistency(mm, nn, a, bb, pp) == _paper_cons(mm, nn, a, bb, pp), (n, m)
            assert verify_consistency(m, n, r0, r1, P)
            assert _paper_cons(m, n, r0, r1, P)
    assert total == 164_224, total  # the count cited in the paper


# --- independent faithful RFC 9162 2.1.4.2 verifier, incl. Step-7 sn==0 -----
# A THIRD oracle, structurally distinct from the recursive _paper_cons model,
# so the harness below is three-way (deployed / recursive model / RFC loop).
def _rfc_cons(first, second, fh, sh, path):
    if first == 0:
        return True
    if first > second:
        return False
    if first == second:
        return fh == sh and not path
    if not path:
        return False
    p = ([fh] + list(path)) if (first & (first - 1)) == 0 else list(path)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = p[0]
    for c in p[1:]:
        if sn == 0:
            return False
        if (fn & 1) or (fn == sn):
            fr = _hnode(c, fr)
            sr = _hnode(c, sr)
            if not (fn & 1):
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _hnode(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == fh and sr == sh and sn == 0


def test_consistency_lied_size_three_way_agreement():
    """Regression for the RFC 9162 Step-7 terminal check (sn==0).

    The deployed iterative verify_consistency, the recursive ConsRec model
    (_paper_cons), and an independent faithful RFC 9162 2.1.4.2 transliteration
    (_rfc_cons) must agree on BOTH the honest family AND the lied-size family.
    The lied-size dimension is the one the historical differential test above
    never varied; it is exactly where the pre-fix verifier (which omitted RFC
    Step 7's terminal sn==0) accepted semantically-false size claims. Flagship:
    a valid 2->3 proof presented as 1->3 with the size-2 root. This test FAILS
    against the pre-fix verifier and passes once sn==0 is restored.
    """
    # Flagship named example: rejected by all three verifiers.
    L = [f"leaf-{i}".encode() for i in range(3)]
    P23 = consistency_proof(L, 2)
    R2, R3 = merkle_root(L[:2]), merkle_root(L)
    assert verify_consistency(1, 3, R2, R3, P23) is False
    assert _paper_cons(1, 3, R2, R3, P23) is False
    assert _rfc_cons(1, 3, R2, R3, P23) is False

    N = 48
    honest_total = lied_total = 0
    for n in range(1, N + 1):
        data = [f"leaf-{i}".encode() for i in range(n)]
        rn = merkle_root(data)
        for m in range(1, n + 1):
            P = consistency_proof(data, m)
            rm = merkle_root(data[:m])
            assert (verify_consistency(m, n, rm, rn, P)
                    == _paper_cons(m, n, rm, rn, P)
                    == _rfc_cons(m, n, rm, rn, P) is True), ("honest", n, m)
            honest_total += 1
            for mlie in range(1, n):
                if mlie == m:
                    continue
                dep = verify_consistency(mlie, n, rm, rn, P)
                mod = _paper_cons(mlie, n, rm, rn, P)
                rfc = _rfc_cons(mlie, n, rm, rn, P)
                assert dep == mod == rfc, ("lied", n, m, mlie, dep, mod, rfc)
                lied_total += 1
    assert honest_total == N * (N + 1) // 2
    assert lied_total == sum((n - 1) ** 2 for n in range(1, N + 1))
