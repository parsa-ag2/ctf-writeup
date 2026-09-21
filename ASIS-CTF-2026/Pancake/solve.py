import json
import hashlib
from Crypto.Cipher import AES

d = json.load(open("challenge.json"))

k1 = hashlib.sha256(b"K1-SEED" + (583324655).to_bytes(4, "big")).digest()
n1 = bytes.fromhex(d["n"][0])
alt = bytes.fromhex("a5720dc7719f529e8e9cb565")

key = hashlib.sha256(b"SEALED-TICKET-KEY" + k1 + n1 + alt).digest()[:16]
iv = hashlib.sha256(b"SEALED-TICKET-IV" + key).digest()[:12]

z = d["z"]
ticket = AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(
    bytes.fromhex(z["c"]), bytes.fromhex(z["t"])
)

keystream = bytes.fromhex(json.loads(ticket)["x"]["c"])
y = bytes.fromhex(d["y"]["c"])

print(bytes(a ^ b for a, b in zip(y, keystream)).decode())