# Pancake — ASIS CTF 2026

> **Room / Challenge:** Pancake (Crypto)

---

## Metadata

* **Author:** `Parsa`
* **CTF:** ASIS CTF 2026
* **Challenge:** Pancake (crypto)
* **Difficulty:** `Easy`
* **Points:** `32`
* **Date:** `29-08-2026` / `7/6/1405`

## Goal

The goal of this challenge was to recover the flag from the data provided in `challenge.json`.

After reading `pancake.py`, I noticed that the challenge generates a random 32-bit `seed` and derives `k1` from it.

Since the seed is only 32 bits, the search space is `2^32`, making a brute-force attack possible.

---

## 1. Recovering the Seed

The challenge provides a `hint` in `challenge.json` that is derived from the secret seed.

By reading `pancake.py`, we can see that the hint is generated using SHA-256.

Therefore, we can brute-force all possible 32-bit seeds and compare the generated hint with the value provided by the challenge.

The recovered seed was:

`583324655`

This gave us:

`k1 = e9d134ee048cf7ee519446c8cf25e9e4cbe62e93407b65e9e9ee4b8fa100e3d0`

---

## 2. Finding the Collision

After recovering `k1`, I looked at how the internal state was generated.

The challenge calculates a value called `j` from `n2` using AES.

This value is then used to derive several other values:

* `w1`
* `w2`
* `r1`
* `r2`

These values are eventually used by the KDF to derive the cryptographic state.

The important part is that we can find another nonce, `alt`, that produces the same `j` value:

`j(n2) = j(alt)`

To find this collision, I brute-forced a 32-bit `sep` value.

The idea is to keep the known 96-bit value fixed and try every possible 32-bit suffix.

For each candidate, we decrypt the resulting AES block.

If the plaintext ends with four zero bytes, the upper 96 bits of the plaintext give us the colliding nonce.

I implemented this brute-force search in `collision.c`.

> **Note:** I used AI assistance for implementing the C brute-force code.

The collision we found was:

`alt = a5720dc7719f529e8e9cb565`

The corresponding `j` value was:

`b33d490e229d120ac40fe003`

---

## 3. Recovering the Keystream

The challenge contains an encrypted object called `z`.

Using the recovered `k1`, `n1`, and `alt`, we can derive the key and IV required to decrypt the sealed ticket.

This part is implemented in `solve.py`.

After decrypting `z`, we get a ticket containing `x.c`.

The plaintext corresponding to this ciphertext is known and consists of zero bytes.

For a stream-like encryption:

`C = P XOR K`

Since:

`P = 0`

we get:

`C = K`

Therefore, `x.c` directly gives us the keystream.

---

## 4. Recovering the Flag

At this point we have:

* The ciphertext `y.c`
* The keystream recovered from `x.c`

Using:

`P = C XOR K`

we can recover the plaintext of `y.c`.

So we XOR `y.c` with the recovered keystream.

This gives us the flag.

---

## 5. Files

The final solver is available in:

`solve.py`

The collision brute-force implementation is:

`collision.c`

The original challenge implementation is:

`pancake.py`

---

## Flag

`ASIS{paNc4kE_v3_Lo5t_!t5_n4mE_8Ut___n0T___iTs_89uG!}`

---

## Conclusion

The complete attack path was:

`32-bit seed`

↓

`Brute-force seed`

↓

`Recover k1`

↓

`Find AES collision`

↓

`Recover alt`

↓

`Decrypt sealed ticket`

↓

`Recover keystream from known plaintext`

↓

`XOR with y.c`

↓

`Recover flag`
