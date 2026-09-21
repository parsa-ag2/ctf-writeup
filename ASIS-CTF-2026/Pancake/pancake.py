#!/usr/bin/env python3

from __future__ import annotations
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from hashlib import sha256, shake_256
from pathlib import Path
from secrets import randbits, token_bytes
from Crypto.Cipher import AES
from flag import flag

BLOCK_SIZE_BITS = 128
DEFAULT_DROP = 32
NONCE_BITS = BLOCK_SIZE_BITS - DEFAULT_DROP
NONCE_MASK = (1 << NONCE_BITS) - 1
DROP_MASK = (1 << DEFAULT_DROP) - 1
KNOWN_PLAINTEXT = bytes(128)

C_SEARCH_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#if defined(__APPLE__)
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>
#else
#include <openssl/aes.h>
#include <openssl/sha.h>
#endif
typedef struct {
	uint8_t key[32];
	uint8_t base[16];
	uint32_t drop;
	uint64_t start;
	uint64_t end;
	int *found_flag;
	uint8_t *result_pt;
} worker_arg_t;
void* worker_aes(void* arg) {
	worker_arg_t *w = (worker_arg_t*)arg;
	uint64_t cur = w->start;
#if defined(__APPLE__)
	CCCryptorRef cryptor;
	CCCryptorCreate(kCCDecrypt, kCCAlgorithmAES, kCCOptionECBMode, w->key, 32, NULL, &cryptor);
	uint8_t in_buf[16 * 4096];
	uint8_t out_buf[16 * 4096];
	size_t moved;
	for (uint32_t i = 0; i < 4096; i++) {
		memcpy(&in_buf[i * 16], w->base, 12);
	}
	while (cur < w->end && !(*w->found_flag)) {
		uint32_t count = (w->end - cur > 4096) ? 4096 : (uint32_t)(w->end - cur);
		for (uint32_t i = 0; i < count; i++) {
			uint32_t suffix = (uint32_t)(cur + i);
			in_buf[i * 16 + 12] = (suffix >> 24) & 0xff;
			in_buf[i * 16 + 13] = (suffix >> 16) & 0xff;
			in_buf[i * 16 + 14] = (suffix >> 8) & 0xff;
			in_buf[i * 16 + 15] = suffix & 0xff;
		}
		CCCryptorUpdate(cryptor, in_buf, count * 16, out_buf, sizeof(out_buf), &moved);
		for (uint32_t i = 0; i < count; i++) {
			uint8_t *b = &out_buf[i * 16];
			if (b[12] == 0 && b[13] == 0 && b[14] == 0 && b[15] == 0) {
				*w->found_flag = 1;
				memcpy(w->result_pt, b, 16);
				CCCryptorRelease(cryptor);
				return NULL;
			}
		}
		cur += count;
	}
	CCCryptorRelease(cryptor);
#else
	AES_KEY dec_key;
	AES_set_decrypt_key(w->key, 256, &dec_key);
	uint8_t in_block[16];
	uint8_t out_block[16];
	memcpy(in_block, w->base, 12);
	while (cur < w->end && !(*w->found_flag)) {
		uint32_t suffix = (uint32_t)cur;
		in_block[12] = (suffix >> 24) & 0xff;
		in_block[13] = (suffix >> 16) & 0xff;
		in_block[14] = (suffix >> 8) & 0xff;
		in_block[15] = suffix & 0xff;
		AES_ecb_encrypt(in_block, out_block, &dec_key, AES_DECRYPT);
		if (out_block[12] == 0 && out_block[13] == 0 && out_block[14] == 0 && out_block[15] == 0) {
			*w->found_flag = 1;
			memcpy(w->result_pt, out_block, 16);
			return NULL;
		}
		cur++;
	}
#endif
	return NULL;
}
int main(int argc, char** argv) {
	if (argc < 4) return 1;
	uint8_t key[32], base[16];
	for (int i = 0; i < 32; i++) sscanf(&argv[1][i*2], "%02hhx", &key[i]);
	for (int i = 0; i < 16; i++) sscanf(&argv[2][i*2], "%02hhx", &base[i]);
	uint32_t drop = atoi(argv[3]);
	uint64_t total = 1ULL << drop;
	int num_threads = 8;
	pthread_t threads[num_threads];
	worker_arg_t args[num_threads];
	int found_flag = 0;
	uint8_t result_pt[16] = {0};
	uint64_t chunk = total / num_threads;
	for (int i = 0; i < num_threads; i++) {
		memcpy(args[i].key, key, 32);
		memcpy(args[i].base, base, 16);
		args[i].drop = drop;
		args[i].start = i * chunk;
		args[i].end = (i == num_threads - 1) ? total : (i + 1) * chunk;
		args[i].found_flag = &found_flag;
		args[i].result_pt = result_pt;
		pthread_create(&threads[i], NULL, worker_aes, &args[i]);
	}
	for (int i = 0; i < num_threads; i++) {
		pthread_join(threads[i], NULL);
	}
	if (found_flag) {
		printf("RESULT:");
		for (int i = 0; i < 16; i++) printf("%02x", result_pt[i]);
		printf("\n");
	} else {
		printf("NO COLLISION\n");
	}
	return 0;
}
"""
COMPILED_BIN_PATH = None
def get_c_binary() -> str | None:
	global COMPILED_BIN_PATH
	if COMPILED_BIN_PATH and os.path.exists(COMPILED_BIN_PATH):
		return COMPILED_BIN_PATH
	compiler = shutil.which("clang") or shutil.which("gcc")
	if not compiler:
		return None
	tmpdir = tempfile.mkdtemp()
	src_path = os.path.join(tmpdir, "search.c")
	bin_path = os.path.join(tmpdir, "search")
	with open(src_path, "w") as f:
		f.write(C_SEARCH_SOURCE)
	flags = ["-O3"]
	if sys.platform != "darwin":
		flags.append("-lcrypto")
	cmd = [compiler] + flags + [src_path, "-o", bin_path]
	ret = subprocess.run(cmd, capture_output=True)
	if ret.returncode == 0:
		COMPILED_BIN_PATH = bin_path
		return bin_path
	return None

def set_drop(v: int) -> None:
	global DEFAULT_DROP, NONCE_BITS, NONCE_MASK, DROP_MASK
	DEFAULT_DROP = v
	NONCE_BITS = BLOCK_SIZE_BITS - DEFAULT_DROP
	NONCE_MASK = (1 << NONCE_BITS) - 1
	DROP_MASK = (1 << DEFAULT_DROP) - 1

def byte_width() -> int:
	return (NONCE_BITS + 7) // 8

def encode_num(x: int) -> str:
	return (x & NONCE_MASK).to_bytes(byte_width(), "big").hex()

def decode_num(x: str) -> int:
	return int.from_bytes(bytes.fromhex(x), "big") & NONCE_MASK

def format_block(x: int, sep: int = 0) -> bytes:
	return (((x & NONCE_MASK) << DEFAULT_DROP) | (sep & DROP_MASK)).to_bytes(16, "big")

def extract_upper(x: bytes) -> int:
	return int.from_bytes(x, "big") >> DEFAULT_DROP

def seed_to_k1(seed: int) -> bytes:
	return sha256(b"K1-SEED" + seed.to_bytes(4, "big")).digest()

def seed_to_hint(seed: int) -> str:
	return sha256(b"K1-SEED-HINT" + seed.to_bytes(4, "big")).hexdigest()

def gf_double(x: int) -> int:
	x &= NONCE_MASK
	carry = x >> (NONCE_BITS - 1)
	x = (x << 1) & NONCE_MASK
	if carry:
		x ^= 0x100000000000000000000013B & NONCE_MASK
	return x

def diffuse_state(k: bytes, n1: int, n2: int) -> tuple[int, int, int, int, int]:
	e = AES.new(k, AES.MODE_ECB)
	j = extract_upper(e.encrypt(format_block(n2, 0)))
	w1 = n1 ^ j
	w2 = n1 ^ gf_double(j)
	r1 = extract_upper(e.encrypt(format_block(w1, 0x18)))
	r2 = extract_upper(e.encrypt(format_block(w2, 0x28)))
	return j, w1, w2, r1, r2

def derive_keys(k2: bytes, n1: int, state: tuple[int, int, int, int, int]) -> tuple[bytes, bytes, bytes]:
	j, w1, w2, r1, r2 = state
	z = shake_256(
		b"KDF-STATE-v1"
		+ k2
		+ n1.to_bytes(byte_width(), "big")
		+ j.to_bytes(byte_width(), "big")
		+ w1.to_bytes(byte_width(), "big")
		+ w2.to_bytes(byte_width(), "big")
		+ r1.to_bytes(byte_width(), "big")
		+ r2.to_bytes(byte_width(), "big")
	).digest(80)
	return z[:16], z[16:28], z[28:44]

def encrypt_authenticated(k1: bytes, k2: bytes, n1: int, n2: int, ad: bytes, msg: bytes) -> dict[str, str]:
	ek, iv, ck = derive_keys(k2, n1, diffuse_state(k1, n1, n2))
	c = AES.new(ek, AES.MODE_GCM, nonce=iv, mac_len=16)
	c.update(ck + ad)
	ct, tag = c.encrypt_and_digest(msg)
	return {"c": ct.hex(), "t": tag.hex()}

def find_collision(k1: bytes, n2: int) -> int | None:
	e = AES.new(k1, AES.MODE_ECB)
	target = extract_upper(e.encrypt(format_block(n2, 0)))
	base = (target << DEFAULT_DROP).to_bytes(16, "big")
	bin_path = get_c_binary()
	if bin_path:
		proc = subprocess.run([bin_path, k1.hex(), base.hex(), str(DEFAULT_DROP)], capture_output=True, text=True)
		for line in proc.stdout.splitlines():
			if line.startswith("RESULT:"):
				pt_hex = line.split(":", 1)[1].strip()
				x = int.from_bytes(bytes.fromhex(pt_hex), "big")
				cand = x >> DEFAULT_DROP
				if cand != n2:
					return cand
	# Python fallback
	base_int = target << DEFAULT_DROP
	for sep in range(1 << DEFAULT_DROP):
		x = int.from_bytes(e.decrypt((base_int | sep).to_bytes(16, "big")), "big")
		if (x & DROP_MASK) == 0:
			y = x >> DEFAULT_DROP
			if y != n2:
				return y
	return None

def seal_sample(k1: bytes, n1: int, n2: int, record: dict[str, object]) -> dict[str, str]:
	key = sha256(b"SEALED-TICKET-KEY" + k1 + n1.to_bytes(byte_width(), "big") + n2.to_bytes(byte_width(), "big")).digest()[:16]
	nonce = sha256(b"SEALED-TICKET-IV" + key).digest()[:12]
	c = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
	blob = json.dumps(record, separators=(",", ":")).encode()
	ct, tag = c.encrypt_and_digest(blob)
	return {"c": ct.hex(), "t": tag.hex()}

def generate(output_path: str = "challenge.json", drop: int = DEFAULT_DROP) -> None:
	set_drop(drop)
	print(f"[*] Generating Hard challenge instance (drop={drop})...", flush=True)
	attempts = 0
	t0 = time.time()
	seed = randbits(32)
	k1 = seed_to_k1(seed)
	hint = seed_to_hint(seed)
	while True:
		attempts += 1
		k2 = token_bytes(32)
		n1 = randbits(NONCE_BITS)
		n2 = randbits(NONCE_BITS)
		alt = find_collision(k1, n2)
		if alt is not None:
			break
	ad = b"AUTH-METADATA-2026"
	sample = encrypt_authenticated(k1, k2, n1, alt, ad, KNOWN_PLAINTEXT)
	ticket = seal_sample(k1, n1, alt, {"n": [encode_num(n1), encode_num(alt)], "x": sample})
	public = {
		"d": DEFAULT_DROP,
		"a": hint,
		"n": [encode_num(n1), encode_num(n2)],
		"h": ad.hex(),
		"m": KNOWN_PLAINTEXT.hex(),
		"y": encrypt_authenticated(k1, k2, n1, n2, ad, flag),
		"z": ticket,
	}
	Path(output_path).write_text(json.dumps(public, separators=(",", ":")), encoding="utf-8")
	print(f"[+] Wrote Hard challenge instance to {output_path} (took {time.time() - t0:.2f}s, {attempts} attempts)", flush=True)

def main() -> None:
	p = argparse.ArgumentParser(description="Authenticated Encryption Challenge")
	p.add_argument("--output", default="challenge.json", help="Path to output challenge json file")
	p.add_argument("--drop", type=int, default=DEFAULT_DROP, help="Truncated bits (default: 32)")
	args = p.parse_args()
	generate(args.output, args.drop)

if __name__ == "__main__":
	main()