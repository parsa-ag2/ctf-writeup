import json
import hashlib
import hmac
from fpylll import IntegerMatrix, LLL, BKZ
N = 128
Q = 268435361
W = 80
R = 5
D = b"\x3a\x91\xf0\x7d\x14\x68\xbc\x29"
def tr(a):
    while len(a) > 1 and a[-1] == 0:
        a.pop()
    return a
def sb(a, b):
    c = [0] * max(len(a), len(b))
    for i in range(len(c)):
        c[i] = (
            (a[i] if i < len(a) else 0)
            -
            (b[i] if i < len(b) else 0)
        ) % Q
    return tr(c)
def ml(a, b):
    c = [0] * (len(a) + len(b) - 1)
    for i in range(len(a)):
        for j in range(len(b)):
            c[i + j] = (
                c[i + j] + a[i] * b[j]
            ) % Q
    return tr(c)
def dv(a, b):
    a = tr([x % Q for x in a])
    b = tr([x % Q for x in b])
    c = [0] * max(
        1,
        len(a) - len(b) + 1
    )
    u = pow(b[-1], -1, Q)
    while a != [0] and len(a) >= len(b):
        k = len(a) - len(b)
        x = a[-1] * u % Q
        c[k] = x
        for i in range(len(b)):
            a[i + k] = (
                a[i + k] - x * b[i]
            ) % Q
        tr(a)
    return tr(c), a
def iv(a):
    m = [1] + [0] * (N - 1) + [1]
    r0 = m
    r1 = [x % Q for x in a]
    t0 = [0]
    t1 = [1]
    while r1 != [0]:
        u, r2 = dv(r0, r1)
        r0 = r1
        r1 = r2
        t0, t1 = (
            t1,
            sb(t0, ml(u, t1))
        )
    if len(r0) != 1:
        raise ValueError("Polynomial is not invertible")
    inv = pow(r0[0], -1, Q)
    t0 = [
        x * inv % Q
        for x in t0
    ]
    _, t0 = dv(t0, m)
    return t0 + [0] * (N - len(t0))
def pm(a, b):
    c = [0] * N
    for i in range(N):
        for j in range(N):
            x = a[i] * b[j]
            k = i + j
            if k < N:
                c[k] = (
                    c[k] + x
                ) % Q
            else:
                c[k - N] = (
                    c[k - N] - x
                ) % Q
    return c
def sh(a, k):
    k %= 2 * N
    s = -1 if k >= N else 1
    if k >= N:
        k -= N
    b = [0] * N
    for i in range(N):
        if i + k < N:
            b[i + k] = s * a[i]
        else:
            b[i + k - N] = -s * a[i]
    return b
def ky(a, b, s):
    u = min(
        tuple(
            sh(a, i) + sh(b, i)
            for i in range(2 * N)
        )
    )
    return hashlib.sha3_256(
        D +
        s +
        bytes(x + 1 for x in u)
    ).digest()
def multiplication_matrix(h):
    M = [[0] * N for _ in range(N)]
    for i in range(N):
        for k in range(N):
            diff = k - i
            if diff >= 0:
                M[i][k] = h[diff]
            else:
                M[i][k] = -h[diff + N]
    return M
def build_lattice(h):
    B = IntegerMatrix(2 * N, 2 * N)
    M = multiplication_matrix(h)
    for i in range(N):
        B[i, i] = 1
    for i in range(N):
        for j in range(N):
            v = M[i][j] % Q
            if v > Q // 2:
                v -= Q
            B[i, N + j] = v
    for i in range(N):
        B[N + i, N + i] = Q
    return B
def normalize_ternary(v):
    a = list(v[:N])
    b = list(v[N:])
    if all(x in (-1, 0, 1) for x in a + b):
        return a, b
    aa = [-x for x in a]
    bb = [-x for x in b]
    if all(x in (-1, 0, 1) for x in aa + bb):
        return aa, bb
    return None
def check_weight(x):
    if len(x) != N:
        return False
    if any(v not in (-1, 0, 1) for v in x):
        return False
    if sum(v != 0 for v in x) != W:
        return False
    if x.count(1) != W // 2:
        return False
    if x.count(-1) != W // 2:
        return False
    return True
def valid_secret(v, h):
    res = normalize_ternary(v)
    if res is None:
        return None
    a, b = res
    if not check_weight(a):
        return None
    if not check_weight(b):
        return None
    try:
        ainv = iv(a)
    except Exception:
        return None
    check = pm(b, ainv)
    if check != h:
        return None
    return a, b
def try_vector(v, h):
    ans = valid_secret(v, h)
    if ans is not None:
        return ans
    return None
def recover(h, idx):
    print()
    print("=" * 72)
    print(f"[*] LOCK {idx + 1}/{R}")
    print("=" * 72)
    print("[*] Building lattice...")
    B = build_lattice(h)
    print("[*] Lattice dimension:",
          2 * N,
          "x",
          2 * N)
    print()
    print("[*] Running LLL...")
    LLL.reduction(B)
    print("[+] LLL complete")
    for i in range(2 * N):
        v = [
            B[i, j]
            for j in range(2 * N)
        ]
        ans = try_vector(v, h)
        if ans is not None:
            print(
                f"[+] Secret found "
                f"in LLL vector {i}"
            )
            return ans
    print()
    print("[!] LLL did not expose secret.")
    print("[*] Starting BKZ...")
    block_sizes = [
        20,
        25,
        30,
        35,
        40,
        45,
        50
    ]
    for block in block_sizes:
        print()
        print(
            f"[*] BKZ block size = {block}"
        )
        par = BKZ.Param(
            block_size=block,
            max_loops=8
        )
        BKZ.reduction(
            B,
            par
        )
        print(
            "[+] BKZ complete"
        )
        for i in range(2 * N):
            v = [
                B[i, j]
                for j in range(2 * N)
            ]
            ans = try_vector(v, h)
            if ans is not None:
                print()
                print(
                    "[+] =================================="
                )
                print(
                    "[+] SECRET RECOVERED!"
                )
                print(
                    "[+] =================================="
                )
                return ans
        print(
            "[*] Checking short-vector combinations..."
        )
        count = min(48, 2 * N)
        vecs = []
        for i in range(count):
            vecs.append([
                B[i, j]
                for j in range(2 * N)
            ])
        for i in range(count):
            for j in range(i + 1, count):
                for sign in (1, -1):
                    v = [
                        vecs[i][k]
                        +
                        sign * vecs[j][k]
                        for k in range(2 * N)
                    ]
                    ans = try_vector(v, h)
                    if ans is not None:
                        print()
                        print(
                            "[+] SECRET RECOVERED!"
                        )
                        return ans
    raise RuntimeError(
        "BKZ failed to recover this lock"
    )
def decrypt(a, b, h, z):
    s = bytes.fromhex(z["S"])
    c = bytes.fromhex(z["C"])
    t = bytes.fromhex(z["T"])
    k = ky(a, b, s)
    u = json.dumps(
        {
            "N": N,
            "Q": Q,
            "H": h
        },
        sort_keys=True,
        separators=(",", ":")
    ).encode()
    expected = hmac.new(
        k,
        D + u + s + c,
        hashlib.sha256
    ).digest()[:16]
    if not hmac.compare_digest(
        t,
        expected
    ):
        raise RuntimeError(
            "HMAC verification failed"
        )
    stream = hashlib.shake_256(
        D + k + s
    ).digest(len(c))
    plaintext = bytes(
        x ^ y
        for x, y in zip(c, stream)
    )
    return plaintext
def main():
    print(
        "[*] Loading flag.enc"
    )
    with open("flag.enc", "r") as f:
        data = json.load(f)
    hs = data["H"]
    cs = data["C"]
    print(
        f"[+] N = {data['N']}"
    )
    print(
        f"[+] Q = {data['Q']}"
    )
    print(
        f"[+] W = {data['W']}"
    )
    print(
        f"[+] Locks = {data['R']}"
    )
    plaintexts = []
    for i in range(R):
        a, b = recover(
            hs[i],
            i
        )
        print(
            "[+] a weight:",
            sum(x != 0 for x in a)
        )
        print(
            "[+] b weight:",
            sum(x != 0 for x in b)
        )
        print(
            "[*] Decrypting ciphertext..."
        )
        m = decrypt(
            a,
            b,
            hs[i],
            cs[i]
        )
        print(
            "[+] HMAC verified!"
        )
        print(
            "[+] Plaintext:",
            m.hex()
        )
        plaintexts.append(m)
    print()
    print("=" * 72)
    print("[*] Recovering flag...")
    print("=" * 72)
    flag = bytearray(
        plaintexts[0]
    )
    for m in plaintexts[1:]:
        for i in range(len(flag)):
            flag[i] ^= m[i]
    flag = bytes(flag)
    print()
    print(
        "[+] FLAG:"
    )
    print(
        flag
    )
    print()
    try:
        print(
            "[+] ASCII:"
        )
        print(
            flag.decode()
        )
    except UnicodeDecodeError:
        print(
            "[!] Flag is not valid UTF-8"
        )
        print(
            "[+] HEX:",
            flag.hex()
        )
if __name__ == "__main__":
    main()
