#!/usr/bin/env python3

import json
import secrets
import sys
from pathlib import Path

try:
	from Crypto.Cipher import AES
	from Crypto.Hash import SHA256
	from Crypto.Protocol.KDF import HKDF
except ModuleNotFoundError:
	from Cryptodome.Cipher import AES
	from Cryptodome.Hash import SHA256
	from Cryptodome.Protocol.KDF import HKDF

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from flag import flag

n, m, d, s = 96, 72, 24, 64
v = n - d
MOD_POLY = 0x13
MUL = [[0] * 16 for _ in range(16)]

def gf_mul(a, b):
	out = 0
	x = a
	y = b
	while y:
		if y & 1:
			out ^= x
		y >>= 1
		x <<= 1
		if x & 0x10:
			x ^= MOD_POLY
		x &= 0xF
	return out

for _a in range(16):
	for _b in range(16):
		MUL[_a][_b] = gf_mul(_a, _b)

def gf_pow(a, e):
	out = 1
	base = a
	exp = e
	while exp:
		if exp & 1:
			out = gf_mul(out, base)
		base = gf_mul(base, base)
		exp >>= 1
	return out

def gf_inv(a):
	if a == 0:
		raise ZeroDivisionError("inverse of zero")
	return gf_pow(a, 14)

def vec_scale(vec, scalar):
	row = MUL[scalar]
	return [row[x] for x in vec]

def vec_add(a, b):
	return [x ^ y for x, y in zip(a, b)]

def r(k, allow_zero=False):
	while True:
		x = [secrets.randbelow(16) for _ in range(k)]
		if allow_zero or any(x):
			return x

def eval_quad(poly, x):
	out = 0
	for i in range(n):
		xi = x[i]
		if not xi:
			continue
		for j in range(i, n):
			cij = poly[i][j]
			if cij and x[j]:
				out ^= MUL[cij][MUL[xi][x[j]]]
	return out

def oil_embed(k_mat, x):
	y = [0] * n
	for i in range(v):
		acc = 0
		for j in range(d):
			if k_mat[i][j] and x[j]:
				acc ^= MUL[k_mat[i][j]][x[j]]
		y[i] = acc
	y[v:] = x[:]
	return y

def build_public_map(k_mat):
	basis = [oil_embed(k_mat, [1 if i == j else 0 for i in range(d)]) for j in range(d)]
	polys = []
	for _ in range(m):
		poly = [[0] * n for _ in range(n)]
		for i in range(n):
			for j in range(i, n):
				if i < v or j < v:
					poly[i][j] = secrets.randbelow(16)
		for i in range(d):
			poly[v + i][v + i] = eval_quad(poly, basis[i])
		for i in range(d):
			for j in range(i + 1, d):
				x = vec_add(basis[i], basis[j])
				poly[v + i][v + j] = eval_quad(poly, x) ^ eval_quad(poly, basis[i]) ^ eval_quad(poly, basis[j])
		polys.append(poly)
	return polys

def monomial_scramble():
	perm = list(range(n))
	secrets.SystemRandom().shuffle(perm)
	scales = [secrets.randbelow(15) + 1 for _ in range(n)]
	inv_scales = [gf_inv(x) for x in scales]
	return perm, scales, inv_scales

def transform_vec(x, perm, scales):
	y = [0] * n
	for i, value in enumerate(x):
		y[perm[i]] = MUL[scales[i]][value]
	return y

def transform_poly(poly, perm, inv_scales):
	out = [[0] * n for _ in range(n)]
	for i in range(n):
		for j in range(i, n):
			coeff = poly[i][j]
			if coeff == 0:
				continue
			new_coeff = MUL[coeff][MUL[inv_scales[i]][inv_scales[j]]]
			a = perm[i]
			b = perm[j]
			if a <= b:
				out[a][b] ^= new_coeff
			else:
				out[b][a] ^= new_coeff
	return out

def pack_poly(poly):
	return "".join(format(poly[i][j], "x") for i in range(n) for j in range(i, n))

def mat_copy(rows):
	return [row[:] for row in rows]

def row_reduce(rows):
	mat = mat_copy(rows)
	if not mat:
		return []
	cols = len(mat[0])
	rix = 0
	for cix in range(cols):
		pivot = None
		for row in range(rix, len(mat)):
			if mat[row][cix]:
				pivot = row
				break
		if pivot is None:
			continue
		mat[rix], mat[pivot] = mat[pivot], mat[rix]
		inv = gf_inv(mat[rix][cix])
		mat[rix] = vec_scale(mat[rix], inv)
		for row in range(len(mat)):
			if row != rix and mat[row][cix]:
				mat[row] = vec_add(mat[row], vec_scale(mat[rix], mat[row][cix]))
		rix += 1
		if rix == len(mat):
			break
	return [row for row in mat if any(row)]


def derive_key(oil_basis, salt):
	material = bytes(x for row in row_reduce(oil_basis) for x in row)
	return HKDF(material, 32, salt, SHA256, context=b"MARIO")

def encrypt_flag(key, nonce, plaintext):
	cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
	cipher.update(b"MARIO")
	ciphertext, tag = cipher.encrypt_and_digest(plaintext)
	return ciphertext + tag

def main():
	k_mat = [r(d) for _ in range(v)]
	polys = build_public_map(k_mat)
	while True:
		g = r(n)
		if any(eval_quad(poly, g) for poly in polys):
			break

	reports = []
	for _ in range(s):
		oil_vec = oil_embed(k_mat, r(d))
		mask = secrets.randbelow(15) + 1
		reports.append(vec_add(oil_vec, vec_scale(g, mask)))

	perm, scales, inv_scales = monomial_scramble()
	public_polys = [transform_poly(poly, perm, inv_scales) for poly in polys]
	public_reports = [transform_vec(report, perm, scales) for report in reports]
	public_oil_basis = [transform_vec(oil_embed(k_mat, [1 if i == j else 0 for i in range(d)]), perm, scales) for j in range(d)]

	salt = secrets.token_bytes(32)
	nonce = secrets.token_bytes(12)
	key = derive_key(public_oil_basis, salt)
	ciphertext = encrypt_flag(key, nonce, flag)

	payload = {
		"F": [16, "x^4+x+1"],
		"p": [n, m, d, s],
		"A": [pack_poly(poly) for poly in public_polys],
		"B": public_reports,
		"C": [salt.hex(), nonce.hex(), ciphertext.hex()],
	}
	Path(__file__).with_name("output.txt").write_text(json.dumps(payload, separators=(",", ":")))

if __name__ == "__main__":
	main()