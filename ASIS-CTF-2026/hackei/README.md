# Hackei — ASIS CTF 2026

> **Room / Challenge:** Hackei (Crypto)

---

## Metadata

* **Author:** `Parsa`
* **CTF:** ASIS CTF 2026
* **Challenge:** Hackei (crypto)
* **Difficulty:** `Easy`
* **Points:** `24`
* **Date:** `29-08-2026` / `7/6/1405`

## Goal

The goal of this challenge is to recover the flag from the given encrypted words.

## My Solution

After connecting to the Hackel Security Service, I checked the public parameters and relations. The hint shows that the service works with algebraic word relations and has separate upper/lower symbols, with mixed relations such as:

```text
Aa = aA
Ab = abaaaaaaaaaA
Bb = bB
Ba = babbbbbbbbbbB
```

The encrypted data consists of words containing only `a` and `b`:

```text
aaaaaaa, aaaaab, aaaaaa, aaaaaaa, ...
```

Since there are only two possible symbols, I treated them as binary values:

```text
a = 0
b = 1
```

Then I grouped the resulting bits into bytes and converted them to ASCII to recover the flag.

### Solve Script

The encrypted data is stored in [`word.txt`](./word.txt).

I used the following Python script in [`solve.py`](./solve.py) to extract the binary data and convert it to ASCII:

```python
import re

text = open("word.txt").read()
words = re.findall(r'\b[ab]+\b', text)

bits = ''.join('1' if 'b' in word else '0' for word in words)

flag = ''.join(
    chr(int(bits[i:i+8], 2))
    for i in range(0, len(bits) - 7, 8)
)

print("Number of words:", len(words))
print("Number of bits:", len(bits))
print("Flag:", flag)
```

The script first extracts the words from `word.txt`, converts them into bits, and then converts every 8 bits into an ASCII character.



