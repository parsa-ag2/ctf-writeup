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

---

## Goal

The challenge uses a custom AES-based construction where a collision in an internal value causes the same encryption state to be derived for two different nonces.

The goal is to exploit this collision and recover the flag.

---

## 1. Recovering the Seed

The challenge provides a SHA-256 based hint derived from a 32-bit seed.

The seed space is only `2^32`, so I brute-forced all possible seeds until the generated hint matched the value in `challenge.json`.

The recovered seed was:

```text
583324655
```

Using this seed, I derived:

```text
k1 =
e9d134ee048cf7ee519446c8cf25e9e4cbe62e93407b65e9e9ee4b8fa100e3d0
```

---

## 2. Finding the Collision

The challenge derives an internal value `j` from:

```text
AES_k1(n2 || 0^32)
```

Then it searches for another nonce `alt` such that:

```text
AES_k1(alt || sep)
```

produces the same upper 96 bits while the lower 32 bits are zero.

I brute-forced the 32-bit `sep` value and found:

```text
alt =
a5720dc7719f529e8e9cb565
```

The resulting collision gives the same `j` value for both nonces.

Therefore:

```text
w1, w2, r1, r2
```

are also identical.

This causes the derived encryption state to be reused.

---

## 3. Recovering the Keystream

The challenge uses AES-GCM and encrypts a known plaintext consisting of 128 zero bytes.

Since:

```text
ciphertext = plaintext XOR keystream
```

and the plaintext is all zeroes:

```text
ciphertext = keystream
```

So the ciphertext inside the decrypted ticket directly gives us the GCM keystream.

First, I decrypted `z` using the sealed-ticket key derived from `k1`, `n1`, and `alt`.

The decrypted ticket contains the known plaintext ciphertext:

```text
ticket["x"]["c"]
```

This gives us the keystream needed to decrypt `y`.

---

## 4. Recovering the Flag

Finally, I XORed the ciphertext from `y` with the recovered keystream:

```text
flag = y.c XOR keystream
```

This recovered the flag.

---

## 5. Files

* `challenge.json` — challenge data
* `pancake.py` — original challenge code
* `solve.py` — final solver
* `collision.c` — C brute-force collision search → **AI**

### About `collision.c`

I used C with OpenSSL to brute-force the 32-bit `sep` space efficiently.

AI was used to help implement the C brute-force search and the OpenSSL-related code.

---

## Flag

```text
ASIS{paNc4kE_v3_Lo5t_!t5_n4mE_8Ut___n0T___iTs_89uG!}
```

---

## Conclusion

The main idea was to find a collision in the challenge's internal AES-derived state.

The collision caused the same GCM encryption state to be reused, allowing the known plaintext inside the ticket to reveal the keystream. XORing this keystream with the target ciphertext then recovered the flag.
