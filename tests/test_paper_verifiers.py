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
