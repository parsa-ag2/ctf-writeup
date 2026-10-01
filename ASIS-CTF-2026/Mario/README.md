# Mario — ASIS CTF 2026

**Room / Challenge:** Mario (Crypto)

**Metadata**

* Author: `Parsa`
* CTF: ASIS CTF 2026
* Challenge: Mario (crypto)
* Difficulty: `Medium`
* Points: `30`
* Date: `29-08-2026` / `7/6/1405`

## Requirements

* `pycryptodome`

## Goal

The goal of this challenge is to recover the flag by analyzing the leaked public cryptographic data and exploiting weaknesses in the construction of the underlying multivariate cryptosystem.

## My Solution

The challenge (`mario.py`) implements a scheme based on the **Unbalanced Oil-and-Vinegar (UOV)** multivariate construction. A secret 24-dimensional "Oil" subspace is generated, a public system of 72 quadratic polynomials in 96 variables is built from it (these vanish identically on the Oil subspace, by construction), and 64 "reports" are published, each of the form:

```text
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

The complete solution script is available here:

[solve.py — Mario](https://github.com/parsa-ag2/ctf-writeup/blob/main/ASIS-CTF-2026/Mario/solve.py?utm_source=chatgpt.com)

The script recovers the hidden Oil subspace and uses the recovered basis to derive the AES key and decrypt the flag.

**Output:**

```text
ASIS{MARY0___grOe8n3r___8aSi5_chA1L3n9e_Mas7eR3d_r3A1Ly?!!!}
```
