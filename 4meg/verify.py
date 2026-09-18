#!/usr/bin/env python3
"""Check the 4 meg test yourself. The write up: https://seed.dogofbitcoin.org/4meg

Block 967,483 holds a 153 byte transaction. Its first output is a taproot key, and that key is a
fingerprint of a script holding a whole 10 second video. This file rebuilds the fingerprint from the
video and the public chain and compares it with the block. Then it rebuilds the 3.85 MB transaction
that carried the video between DOG Mode nodes, and the 1 sat transaction before it, and checks each
against the id we published on the day.

    python3 verify.py dog.mp4
    python3 verify.py dog.mp4 --api https://blockstream.info/api    # any esplora API, or your own

Published by the Dog of Bitcoin Foundation at https://github.com/dogofbitcoin/dogmode-relay-tests, beside the video.

Python 3.8 or newer, standard library only. It reads two confirmed transactions from the API and
nothing else, and it holds no key: it only ever checks.
"""
import argparse
import hashlib
import json
import sys
import urllib.request

COMMIT = "b7edb847dfa0a150f70874096d8ea70c6b13958f777ea8e84d77063d7f09c0d4"    # block 967,483
FUNDING = "dd8ee0a3698781019d22963cf8c066259ee8bda34b27731505b3d6645e51b2f8"   # block 966,980
VIDEO_SHA256 = "b3c9e3d8cb88dad1407dd43da8c5b30f114f42112eec1753589ff376b39ec937"
REVEAL_TXID = "5d072e6797b1ecec273f5e9b0eb60aa5fc231f70fee86d3a0d52e4184ee3c29a"
DUST_TXID = "7a2aacd3ca2bf1b180c55d5c40254d627632ba91e2f3d956b061a6acc34b3e8a"
CORE_LIMIT, DOGMODE_LIMIT = 400_000, 3_900_000    # the most weight each will relay, in weight units

# secp256k1, only what it takes to tweak one key (BIP340, BIP341)
P = 2**256 - 2**32 - 977
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        m = 3 * a[0] * a[0] * pow(2 * a[1], P - 2, P) % P
    else:
        m = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (m * m - a[0] - b[0]) % P
    return x, (m * (a[0] - x) - a[1]) % P


def mul(k, pt):
    out = None
    while k:
        if k & 1:
            out = add(out, pt)
        pt, k = add(pt, pt), k >> 1
    return out


def lift_x(x):
    """The point with this x and an even y, the way taproot reads a 32 byte key."""
    c = (pow(x, 3, P) + 7) % P
    y = pow(c, (P + 1) // 4, P)
    if y * y % P != c:
        sys.exit("that key is not a point on the curve")
    return x, y if y % 2 == 0 else P - y


def tagged(tag, msg):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def push(b):
    if len(b) < 0x4C:
        return bytes([len(b)]) + b
    if len(b) <= 0xFF:
        return b"\x4c" + bytes([len(b)]) + b
    return b"\x4d" + len(b).to_bytes(2, "little") + b


def envelope(key, video, content_type=b"video/mp4"):
    """The script the video rode in, byte for byte the ordinals envelope."""
    s = push(key) + b"\xac"                        # <key> OP_CHECKSIG: the only part that ever runs
    s += b"\x00\x63"                               # OP_FALSE OP_IF: everything up to OP_ENDIF is skipped
    s += push(b"ord") + push(b"\x01") + push(content_type) + b"\x00"   # "ord", tag 1 = content type, then the body
    for i in range(0, len(video), 520):            # 520 bytes is the most one push may carry
        s += push(video[i:i + 520])
    return s + b"\x68"                             # OP_ENDIF


def taproot_key(key, script):
    """The output key a single leaf taproot address commits to (BIP341)."""
    leaf = tagged("TapLeaf", b"\xc0" + varint(len(script)) + script)
    t = int.from_bytes(tagged("TapTweak", key + leaf), "big")
    q = add(lift_x(int.from_bytes(key, "big")), mul(t, G))    # the internal key, tweaked by the script's hash
    return q[0].to_bytes(32, "big")


def unsigned(prev_txid, vout, outputs):
    """Version 2, one input, sequence 0xfffffffd, locktime 0, no witness: the bytes a txid hashes."""
    b = (2).to_bytes(4, "little") + b"\x01" + bytes.fromhex(prev_txid)[::-1] + vout.to_bytes(4, "little")
    b += b"\x00" + (0xFFFFFFFD).to_bytes(4, "little") + varint(len(outputs))
    for value, spk in outputs:
        b += value.to_bytes(8, "little") + varint(len(spk)) + spk
    return b + b"\x00\x00\x00\x00"


def txid(raw):
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()


def check(results, label, ok, detail=""):
    results.append(ok)
    print(("PASS  " if ok else "FAIL  ") + label + (f"\n      {detail}" if detail else ""))


def run(video, commit, funding):
    """commit and funding are the two transactions as an esplora API returns them (JSON)."""
    results = []
    check(results, "the video is the file that was sent", hashlib.sha256(video).hexdigest() == VIDEO_SHA256,
          f"{len(video):,} bytes, sha256\n      {hashlib.sha256(video).hexdigest()}")

    key = bytes.fromhex(commit["vin"][0]["witness"][1])[1:]   # the test key, from the witness that funded the commit
    home = bytes.fromhex(commit["vout"][1]["scriptpubkey"])     # the test key's own address, the commit's change
    spk = commit["vout"][0]["scriptpubkey"]                     # 5120 then the key: OP_1, a 32 byte push
    on_chain = spk[4:] if spk.startswith("5120") and len(spk) == 68 else "not a taproot output"
    script = envelope(key, video)
    rebuilt = taproot_key(key, script).hex()
    height = commit.get("status", {}).get("block_height")
    check(results, f"block {height:,} committed to exactly this video" if height else "the commit matches this video",
          rebuilt == on_chain, f"on chain  {on_chain}\n      rebuilt   {rebuilt}")

    # The reveal: spends the commit's first output, pays 1,000 sats back to the test key. A txid never
    # covers the witness, so the id is rebuilt from the unsigned part and the weight from the parts' sizes.
    raw = unsigned(COMMIT, 0, [(1000, home)])
    witness = 2 + 1 + (1 + 64) + len(varint(len(script))) + len(script) + (1 + 33)   # marker, flag, count, signature, script, control block
    weight = 4 * len(raw) + witness
    vsize = -(-weight // 4)
    fee = commit["vout"][0]["value"] - 1000
    check(results, "the 3.85 MB transaction's id", txid(raw) == REVEAL_TXID, f"rebuilt {txid(raw)}")
    check(results, f"it weighs {weight:,} WU, {weight / CORE_LIMIT:.1f} times what Bitcoin Core relays",
          CORE_LIMIT < weight <= DOGMODE_LIMIT,
          f"Core relays up to {CORE_LIMIT:,}, DOG Mode up to {DOGMODE_LIMIT:,}, a block holds 4,000,000")
    print(f"      {vsize:,} vB at {fee / vsize:.3f} sat/vB, {fee:,} sats of fee offered, never paid:\n"
          "      the coin was spent back first")

    # The 1 sat test: one output of 1 sat to the test key (Core calls anything under 294 sats dust
    # on this kind of address), the change back to it, 141 sats of fee.
    value = funding["vout"][0]["value"]
    raw = unsigned(FUNDING, 0, [(1, home), (value - 1 - 141, home)])
    check(results, "the 1 sat transaction's id", txid(raw) == DUST_TXID, f"rebuilt {txid(raw)}")
    return all(results)


def fetch(api, tx):
    req = urllib.request.Request(f"{api.rstrip('/')}/tx/{tx}", headers={"User-Agent": "dogmode-4meg-verify"})
    with urllib.request.urlopen(req, timeout=30) as r:
        if r.status != 200:
            sys.exit(f"{api} answered HTTP {r.status} for {tx}")
        return json.load(r)


def main():
    ap = argparse.ArgumentParser(description="Check the 4 meg test against the chain.")
    ap.add_argument("video", help="dog.mp4, beside this file in the repository")
    ap.add_argument("--api", default="https://mempool.space/api", help="an esplora API (default: mempool.space)")
    a = ap.parse_args()
    with open(a.video, "rb") as f:
        video = f.read()
    ok = run(video, fetch(a.api, COMMIT), fetch(a.api, FUNDING))
    print("\nEverything matches." if ok else
          "\nSomething does not match. Open an issue: https://github.com/dogofbitcoin/dogmode-relay-tests/issues")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
