# Fence — ASIS CTF 2026

> **Room / Challenge:** Fence (Crypto)

---

## Metadata

* **Author:** `Parsa`
* **CTF:** ASIS CTF 2026
* **Challenge:** Fence (Crypto)
* **Difficulty:** `Hard`
* **Date:** `29-08-2026` / `7/6/1405`

---

## Requirements

* `fpylll`
* `cysignals`

---

## Goal

The challenge implements an NTRU-like lattice-based cryptosystem.

The goal is to recover the small secret polynomials `a` and `b` from the public value `h`, derive the encryption key, verify the ciphertext using HMAC, and finally recover the flag.

---

## 1. Analyzing the Challenge

The challenge works with polynomials of degree `128` over the ring:

```text
Z_q[x] / (x^128 + 1)
```

where:

```text
q = 268435361
```

The public value is generated from two small secret polynomials:

```text
h = b * a^-1 mod q
```

The secret polynomials have coefficients restricted to:

```text
-1, 0, 1
```

with exactly `40` coefficients equal to `1`, `40` equal to `-1`, and the remaining `48` coefficients equal to `0`.

This small structure makes the secret vectors suitable for a lattice attack.

---

## 2. Recognizing the Lattice Problem

The equation:

```text
h * a = b mod q
```

can be rewritten as:

```text
h * a - b = 0 mod q
```

This gives us a relation between the unknown vectors `a` and `b`.

Because both vectors are small, we can construct a lattice containing this relation and search for a short vector corresponding to the secret polynomials.

---

## 3. Building the Lattice

The solver constructs a `256 × 256` lattice matrix.

The first `128` dimensions represent the coefficients of `a`, while the other `128` dimensions represent the relation involving the public polynomial `h` and the modulus `q`.

The important property is that a lattice vector containing the correct `(a, b)` pair will be unusually short because its coefficients are only:

```text
-1, 0, 1
```

---

## 4. LLL and BKZ

The first reduction attempt uses LLL to reduce the lattice.

However, LLL alone is not sufficient to reliably recover the secret vectors.

Therefore, the solver also applies BKZ with several block sizes:

```text
20
30
40
```

After each reduction, the resulting vectors are checked.

A candidate is accepted only if:

```text
a.count(1)  == 40
a.count(-1) == 40
b.count(1)  == 40
b.count(-1) == 40
```

and the polynomial relation holds:

```text
a * h = b mod q
```

Once these conditions are satisfied, the secret polynomials have been recovered.

---

## 5. Recovering the Key

After recovering `a` and `b`, the challenge's key derivation process is reproduced.

The solver applies the same transformations used by the challenge, including the cyclic shifts of the recovered polynomials.

The resulting material is then hashed using:

```text
SHA3-256
```

together with the challenge constant and salt.

This produces the encryption key.

---

## 6. Verifying the Ciphertext

The encrypted data contains:

```text
S
C
T
```

where:

* `S` is the salt
* `C` is the ciphertext
* `T` is the authentication tag

The solver recreates the challenge's JSON structure and calculates:

```text
HMAC-SHA256
```

using the recovered key.

The calculated tag is then compared with the provided tag.

If they match, the recovered secret polynomials and derived key are confirmed to be correct.

---

## 7. Decrypting the Ciphertext

After successful HMAC verification, the solver generates the same keystream used by the challenge:

```text
SHAKE-256(D || key || salt)
```

The ciphertext is then XORed with the keystream:

```text
plaintext = ciphertext XOR keystream
```

The recovered plaintexts are then XORed together to obtain the final flag.

---

## 8. Solve Script

The complete solution script is available here:

[solve.py — Fence](https://github.com/parsa-ag2/ctf-writeup/blob/main/ASIS-CTF-2026/Fence/solve.py?utm_source=chatgpt.com)

The script constructs the lattice, applies LLL/BKZ to recover the secret polynomials, derives the encryption key, verifies the HMAC, and decrypts the ciphertext.

---

## Flag

```text
ASIS{qu4ntum_c0h3r3nc3_1n_0v3r5tr3t3d_h4rm0n1c_f13ld5!}
```

---

## Conclusion

The main weakness was the small and highly structured secret polynomials used by the NTRU-like construction.

By converting the public polynomial relation into a lattice problem and applying LLL/BKZ reduction, the secret polynomials could be recovered.

The recovered values were then used to reproduce the key derivation, verify the ciphertext, and decrypt the final flag.
