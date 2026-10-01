#!/usr/bin/env python3

import hashlib
import hmac
import json
import secrets


n = 128
q = 268435361
w = 80
d = b"\x3a\x91\xf0\x7d\x14\x68\xbc\x29"
r = 5


def tr(a):
	while len(a) > 1 and a[-1] == 0:
		a.pop()
	return a


def sb(a, b):
	c = [0] * max(len(a), len(b))
	for i in range(len(c)):
		c[i] = ((a[i] if i < len(a) else 0) - (b[i] if i < len(b) else 0)) % q
	return tr(c)


def ml(a, b):
	c = [0] * (len(a) + len(b) - 1)
	for i in range(len(a)):
		for j in range(len(b)):
			c[i + j] = (c[i + j] + a[i] * b[j]) % q
	return tr(c)


def dv(a, b):
	a, b = tr([i % q for i in a]), tr([i % q for i in b])
	c = [0] * max(1, len(a) - len(b) + 1)
	u = pow(b[-1], -1, q)
	while a != [0] and len(a) >= len(b):
		k = len(a) - len(b)
		x = a[-1] * u % q
		c[k] = x
		for i in range(len(b)):
			a[i + k] = (a[i + k] - x * b[i]) % q
		tr(a)
	return tr(c), a


def iv(a):
	m = [1] + [0] * (n - 1) + [1]
	r0, r1, t0, t1 = m, [i % q for i in a], [0], [1]
	while r1 != [0]:
		u, r2 = dv(r0, r1)
		r0, r1 = r1, r2
		t0, t1 = t1, sb(t0, ml(u, t1))
	if len(r0) != 1:
		raise ValueError
	t0 = [i * pow(r0[0], -1, q) % q for i in t0]
	_, t0 = dv(t0, m)
	return t0 + [0] * (n - len(t0))


def pm(a, b):
	c = [0] * n
	for i in range(n):
		for j in range(n):
			if i + j < n:
				c[i + j] = (c[i + j] + a[i] * b[j]) % q
			else:
				c[i + j - n] = (c[i + j - n] - a[i] * b[j]) % q
	return c


def sh(a, k):
	k %= 2 * n
	s = -1 if k >= n else 1
	if k >= n:
		k -= n
	b = [0] * n
	for i in range(n):
		if i + k < n:
			b[i + k] = s * a[i]
		else:
			b[i + k - n] = -s * a[i]
	return b


def ky(a, b, s):
	u = min(tuple(sh(a, i) + sh(b, i)) for i in range(2 * n))
	return hashlib.sha3_256(d + s + bytes(i + 1 for i in u)).digest()


def en(a, b, h, m):
	s = secrets.token_bytes(16)
	k = ky(a, b, s)
	z = hashlib.shake_256(d + k + s).digest(len(m))
	c = bytes(i ^ j for i, j in zip(m, z))
	u = json.dumps({"N": n, "Q": q, "H": h}, sort_keys=True, separators=(",", ":")).encode()
	t = hmac.new(k, d + u + s + c, hashlib.sha256).digest()[:16]
	return {"S": s.hex(), "C": c.hex(), "T": t.hex()}


def dc(a, b, h, z):
	s, c, t = bytes.fromhex(z["S"]), bytes.fromhex(z["C"]), bytes.fromhex(z["T"])
	k = ky(a, b, s)
	u = json.dumps({"N": n, "Q": q, "H": h}, sort_keys=True, separators=(",", ":")).encode()
	if not hmac.compare_digest(t, hmac.new(k, d + u + s + c, hashlib.sha256).digest()[:16]):
		raise ValueError
	z = hashlib.shake_256(d + k + s).digest(len(c))
	return bytes(i ^ j for i, j in zip(c, z))


def gn():
	r = secrets.SystemRandom()
	i = list(range(n))
	r.shuffle(i)
	a = [0] * n
	for j in i[:w // 2]:
		a[j] = 1
	for j in i[w // 2:w]:
		a[j] = -1
	return a


def main():
	from flag import flag

	hs, cs = [], []
	acc = [0] * len(flag)
	for idx in range(r):
		while True:
			a, b = gn(), gn()
			try:
				h = pm(b, iv(a))
				break
			except ValueError:
				pass
		if idx < r - 1:
			m = secrets.token_bytes(len(flag))
			acc = [i ^ j for i, j in zip(acc, m)]
		else:
			m = bytes(i ^ j for i, j in zip(acc, flag))
		hs.append(h)
		cs.append(en(a, b, h, m))
	z = {"N": n, "Q": q, "W": w, "R": r, "H": hs, "C": cs}
	with open("flag.enc", "w") as f:
		json.dump(z, f, indent=2)


if __name__ == "__main__":
	main()