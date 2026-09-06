# Mario — ASIS CTF 2026

**Room / Challenge:** Mario (Crypto)

**Metadata**

* Author: `Parsa`
* CTF: ASIS CTF 2026
* Challenge: Mario (crypto)
* Difficulty: `Medium`
* Points: `30`
* Date: `29-08-2026` / `7/6/1405`

## Goal

The goal of this challenge is to recover the flag by analyzing the leaked public cryptographic data and exploiting weaknesses in the construction of the underlying multivariate cryptosystem.

## My Solution

The challenge (`mario.py`) implements a scheme based on the **Unbalanced Oil-and-Vinegar (UOV)** multivariate construction. A secret 24-dimensional "Oil" subspace is generated, a public system of 72 quadratic polynomials in 96 variables is built from it (these vanish identically on the Oil subspace, by construction), and 64 "reports" are published, each of the form:

```
report_i = Oil_i + a_i * g
```

where `Oil_i` is a fresh point of the hidden Oil subspace, `g` is a fixed secret vector, and `a_i` is a random nonzero scalar in GF(16).

To hide the algebraic structure, the challenge is supposed to apply a random invertible linear map to all 96 variables before publishing anything. Instead, `monomial_scramble()` only applies a **permutation + per-coordinate scalar multiplication** — i.e. a monomial matrix, not a general linear map. This means variables are never mixed with each other; the public data is just a relabeled/rescaled copy of the private structure.

**Exploiting it:**

1. Since `a_i` only takes one of 15 possible nonzero values, among 64 reports some pairs `(i, j)` are guaranteed to share the same mask `a_i = a_j`.
2. For such a pair, `report_i XOR report_j = Oil_i XOR Oil_j`, which cancels `g` out completely and lands exactly inside the hidden 24-dimensional Oil subspace.
3. Every public quadratic polynomial vanishes on the Oil subspace by construction, so testing a candidate difference against all 72 public polynomials confirms whether it's a genuine Oil vector.
4. Collecting independent Oil vectors from different pairs (they don't need to come from 24 disjoint reports — a single report can contribute to several valid pairs) until reaching rank 24 fully recovers the hidden Oil subspace.
5. The challenge derives its AES key by row-reducing the (secret) Oil basis and feeding it to HKDF. Reproducing that exact row-reduction on our recovered basis gives the same key, letting us decrypt the flag with AES-GCM using the published `salt`, `nonce`, and `ciphertext`.

## Solve Script

The public data is stored in `output.txt`. I used the following Python script (`solve.py`) to recover the Oil subspace and decrypt the flag:

```python
#!/usr/bin/env python3

import json, sys
from pathlib import Path
try:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import HKDF
except ModuleNotFoundError:
    from Cryptodome.Cipher import AES
    from Cryptodome.Hash import SHA256
    from Cryptodome.Protocol.KDF import HKDF

N, D = 96, 24
MOD_POLY = 0x13

def gf_mul(a, b):
    out = 0
    while b:
        if b & 1: out ^= a
        b >>= 1
        a <<= 1
        if a & 0x10: a ^= MOD_POLY
        a &= 0xF
    return out

MUL = [[gf_mul(a, b) for b in range(16)] for a in range(16)]

def gf_inv(a):
    out, base, e = 1, a, 14
    while e:
        if e & 1: out = MUL[out][base]
        base = MUL[base][base]
        e >>= 1
    return out

def xor_vec(a, b):
    return [x ^ y for x, y in zip(a, b)]

def unpack_poly(s):
    poly, pos = [[0]*N for _ in range(N)], 0
    for i in range(N):
        for j in range(i, N):
            poly[i][j] = int(s[pos], 16); pos += 1
    return poly

def eval_quad(poly, x):
    out = 0
    for i in range(N):
        xi = x[i]
        if not xi: continue
        row = poly[i]
        for j in range(i, N):
            c = row[j]
            if c and x[j]:
                out ^= MUL[c][MUL[xi][x[j]]]
    return out

def row_reduce(rows):
    mat = [row[:] for row in rows]
    rix = 0
    for cix in range(len(mat[0]) if mat else 0):
        pivot = next((r for r in range(rix, len(mat)) if mat[r][cix]), None)
        if pivot is None: continue
        mat[rix], mat[pivot] = mat[pivot], mat[rix]
        inv = gf_inv(mat[rix][cix])
        mat[rix] = [MUL[inv][x] for x in mat[rix]]
        for r in range(len(mat)):
            if r != rix and mat[r][cix]:
                f = mat[r][cix]
                mat[r] = [a ^ MUL[f][b] for a, b in zip(mat[r], mat[rix])]
        rix += 1
        if rix == len(mat): break
    return [row for row in mat if any(row)]

def rank_add(basis, vec):
    v = vec[:]
    for row in basis:
        piv = next(k for k, x in enumerate(row) if x)
        if v[piv]:
            f = MUL[v[piv]][gf_inv(row[piv])]
            v = [a ^ MUL[f][b] for a, b in zip(v, row)]
    if not any(v):
        return False
    basis.append(v)
    return True

data = json.loads(Path(sys.argv[1] if len(sys.argv) > 1 else "output.txt").read_text())
polys = [unpack_poly(p) for p in data["A"]]
B = [[int(x) for x in row] for row in data["B"]]
salt_hex, nonce_hex, ct_hex = data["C"]

oil_basis = []
for i in range(len(B)):
    for j in range(i + 1, len(B)):
        x = xor_vec(B[i], B[j])
        if any(eval_quad(poly, x) for poly in polys):
            continue
        if rank_add(oil_basis, x):
            print(f"[+] oil vector from pair ({i},{j}), rank={len(oil_basis)}")
        if len(oil_basis) == D:
            break
    if len(oil_basis) == D:
        break

assert len(oil_basis) == D, "failed to recover full oil space"

material = bytes(x for row in row_reduce(oil_basis) for x in row)
key = HKDF(material, 32, bytes.fromhex(salt_hex), SHA256, context=b"MARIO")

blob = bytes.fromhex(ct_hex)
cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(nonce_hex))
cipher.update(b"MARIO")
flag = cipher.decrypt_and_verify(blob[:-16], blob[-16:])
print(flag.decode())
```

**Output:**
```
ASIS{MARY0___grOe8n3r___8aSi5_chA1L3n9e_Mas7eR3d_r3A1Ly?!!!}
```
