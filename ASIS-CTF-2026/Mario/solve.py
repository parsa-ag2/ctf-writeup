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

# --- GF(16) arithmetic ---
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
    """Try to insert vec into basis (list of already-echelon rows). Returns True if it raised the rank."""
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

# --- load challenge output ---
data = json.loads(Path(sys.argv[1] if len(sys.argv) > 1 else "output.txt").read_text())
polys = [unpack_poly(p) for p in data["A"]]
B = [[int(x) for x in row] for row in data["B"]]
salt_hex, nonce_hex, ct_hex = data["C"]

# --- recover the Oil subspace from same-mask report pairs ---
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

# --- reproduce the challenge's key derivation ---
material = bytes(x for row in row_reduce(oil_basis) for x in row)
key = HKDF(material, 32, bytes.fromhex(salt_hex), SHA256, context=b"MARIO")

blob = bytes.fromhex(ct_hex)
cipher = AES.new(key, AES.MODE_GCM, nonce=bytes.fromhex(nonce_hex))
cipher.update(b"MARIO")
flag = cipher.decrypt_and_verify(blob[:-16], blob[-16:])
print(flag.decode())
