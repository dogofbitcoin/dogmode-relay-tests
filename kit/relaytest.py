#!/usr/bin/env python3
"""Mainnet relay tests for DOG Mode: send what Bitcoin Core refuses through one DOG Mode node, and read it
arriving in the others while a Core-policy node never sees it. By the Dog of Bitcoin Foundation.

  1. dust  a transaction with a 1 sat output. Core calls anything under 294 sats dust on a P2WPKH address.
  2. big   up to 3,900,000 WU, the most a DOG Mode node relays. Core stops at 400,000. By default it carries
           its bytes the way inscriptions do (a commit, then a taproot reveal); --inscribe FILE makes them a
           real ordinals envelope.

The third reading on every run is the control: a Core-policy explorer (mempool.space by default) must NOT
have the transaction. Seeing it in the other dog nodes and not there is the whole proof that DOG Mode
policy relays what Core drops.

    python3 relaytest.py key              make (or show) the throwaway key and its address
    python3 relaytest.py status           every node, the key's coins, the price, what each test costs
    python3 relaytest.py preflight --inscribe FILE [--feerate 0.1] [--fund N]
                                          OFFLINE: build the whole big test against a made up coin and prove
                                          it, the money's way back included, before you fund anything
    python3 relaytest.py dust [--go]      build the 1 sat test, testmempoolaccept on every node; --go sends it
    python3 relaytest.py big [--inscribe FILE] [--feerate 0.1] [--go]
    python3 relaytest.py watch TXID       where a txid is right now: every node, and the control
    python3 relaytest.py decode TXID [--expect FILE]
                                          pull the transaction back out of each node's mempool, read the
                                          envelope, write the file, hash it against the original
    python3 relaytest.py reclaim [--go]   spend the big test's coin back to the key by key path, through the
                                          control, so the oversized transaction can never be mined
    python3 relaytest.py sweep ADDRESS [--go]
                                          every confirmed coin at the key out to your own wallet

Every command that could spend is a dry run until you add --go. Needs embit (`pip install -r
requirements.txt`) and a config naming your nodes (nodes.example.json; --config, or DOGMODE_RELAYTEST_CONFIG,
or ~/.dogmode-relaytest/nodes.json). The first node sends; every node is asked and watched.

The key: a throwaway P2WPKH key made by `key`, in a file on THIS machine (mode 600), never copied anywhere.
Fund it with only what a test needs and sweep it home after. Signing is local: the nodes only ever see
signed hex, and nothing here puts a key on a server.

What a test costs. THE FLOOR IS 0.1 sat/vB, not 1: Core's own `minrelaytxfee` default since v30 is 1e-06
BTC/kvB, and DOG Mode 31.1 inherits it, so run the big test at `--feerate 0.1`.
  dust    about 140 sats of fee at 1 sat/vB, and it is never mined, so never paid: `sweep` replaces it.
  big     the whole reveal fee IF a miner mines it: about 96,000 sats at 0.1 sat/vB. Core-policy miners
          never see it, and `reclaim` spends the same coin back through the control; once that confirms
          the big transaction is conflicted and every dog mempool drops it. Taking it would be a losing trade
          for a miner anyway: it fills 96 percent of a block that would otherwise pay more. On 2026-09-17 the
          cheapest of the 150 blocks before our run paid 257,733 sats in fees.
  Our two runs (2026-09-14 and 2026-09-17) cost 1,268 sats in fees, start to finish, funding included.

Scars, each one paid for on mainnet:
  - `getmempoolentry` on a txid the node has not seen is an error, not an empty answer; the poll treats
    the error as "not yet".
  - A Core node answers 404 for a dust or oversized transaction forever; that is the control reading, not a
    failure. Ask an esplora API for the full `/tx/<txid>`, never `/tx/<txid>/status`, which answers
    {"confirmed":false} with HTTP 200 even for a txid that does not exist.
  - Do not RBF the big transaction on a dog node: a replacement must pay MORE than its whole fee there.
    The reclaim goes through Core nodes, which never had the big one, at a normal fee.
  - A single execve argument dies over 128 KB (MAX_ARG_STRLEN), and a 3.9 MB transaction is 7.7 MB of hex.
    Every call to a node goes on stdin (`bitcoin-cli -stdin`), never as an argument.
  - embit's `sighash_taproot` needs `ext_flag=1` for a script path spend; without it every node answers
    `Invalid Schnorr signature` while embit verifies its own signature happily. The kit writes the BIP341
    message itself and refuses to sign when embit's disagrees (`bip341_sighash`).
  - A txid in your notes is not a send: a dry run prints the same segwit txid as --go. The state file's
    `sent_at` and the control's full transaction are what say it went out.
"""
import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

try:
    from embit import ec, hashes, script
    from embit.networks import NETWORKS
    from embit.transaction import SIGHASH, Transaction, TransactionInput, TransactionOutput
    from embit.util import secp256k1
except ImportError as e:
    sys.exit(f"embit is missing ({e}): pip install -r requirements.txt, then run with that python")

HOME = Path.home() / ".dogmode-relaytest"
DEFAULTS = {"api": "https://mempool.space/api", "key_file": str(HOME / "key"), "state_file": str(HOME / "state.json"),
            "record_dir": None, "out_dir": "."}

MAX_STANDARD_TX_WEIGHT = 3_900_000     # DOG Mode's limit; Core's is 400,000
MAX_DATACARRIER = 975_000              # DOG Mode's default -datacarriersize; Core's is 100,000
DOG_BIT = 1 << 14

# For a node that runs the Dog of Bitcoin DOG Mode package on umbrelOS ({"umbrel": "user@host"} in the config).
# It runs ON the Umbrel host: it reads the app's RPC user and password from the app's own .env there and asks the
# app's bitcoind at the package's fixed address, so the password never leaves the box. The call arrives on STDIN
# as one JSON object, never as an argument (the execve scar above).
UMBREL_RPC_PY = r'''
import json, sys, re, base64, urllib.request, urllib.error
call = json.load(sys.stdin)
env = open("/home/umbrel/umbrel/app-data/dogofbitcoin-dogmode/.env").read()
def g(k):
    m = re.search(r"^export %s='([^']*)'" % k, env, re.M)
    return m.group(1) if m else ""
body = json.dumps({"jsonrpc": "1.0", "id": "relaytest", "method": call["method"], "params": call.get("params", [])}).encode()
auth = base64.b64encode((g("APP_BITCOIN_DOGMODE_RPC_USER") + ":" + g("APP_BITCOIN_DOGMODE_RPC_PASS")).encode()).decode()
# APP_BITCOIN_DOGMODE_NODE_IP and _RPC_PORT, as the package's exports.sh fixes them
req = urllib.request.Request("http://10.21.21.117:8432/", data=body, headers={"Authorization": "Basic " + auth, "Content-Type": "application/json"})
try:
    with urllib.request.urlopen(req, timeout=300) as r:
        sys.stdout.write(r.read().decode())
except urllib.error.HTTPError as e:
    sys.stdout.write(e.read().decode())
'''


def utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ---------------------------------------------------------------- the config and the nodes

class Node:
    """One DOG Mode node, reached one of two ways:

    {"name": "mine", "cli": "bitcoin-cli -stdin {method}"}   any shell command that ends in bitcoin-cli with
        -stdin and {method}: local, over ssh, through docker exec. The call's arguments go on its stdin.
    {"name": "home", "umbrel": "umbrel@umbrel.local"}        the DOG Mode package on umbrelOS, over ssh."""

    def __init__(self, spec):
        self.name = str(spec.get("name") or "").strip()
        self.cli, self.umbrel = spec.get("cli"), spec.get("umbrel")
        if not self.name:
            sys.exit(f"a node in the config has no name: {spec}")
        if bool(self.cli) == bool(self.umbrel):
            sys.exit(f"node {self.name}: give exactly one of \"cli\" or \"umbrel\"")
        if self.cli and "{method}" not in self.cli:
            sys.exit(f"node {self.name}: the cli command must contain {{method}}, after bitcoin-cli -stdin")

    def rpc(self, method, *params):
        """The RPC's result, or {"_error": message}. Strings go as they are, anything else as JSON."""
        if not re.fullmatch(r"[a-z]+", method):
            raise ValueError(f"not an RPC method name: {method!r}")
        if self.cli:
            lines = "".join((p if isinstance(p, str) else json.dumps(p)) + "\n" for p in params)
            p = subprocess.run(self.cli.format(method=method), shell=True, input=lines,
                               capture_output=True, text=True, timeout=600)
            out = p.stdout.strip()
            if p.returncode != 0:
                return {"_error": (p.stderr.strip() or out)[:400]}
            try:
                return json.loads(out) if out else {}
            except json.JSONDecodeError:
                return out
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=12", self.umbrel, "python3", "-c", shlex.quote(UMBREL_RPC_PY)]
        p = subprocess.run(cmd, input=json.dumps({"method": method, "params": list(params)}),
                           capture_output=True, text=True, timeout=600)
        if p.returncode != 0 and not p.stdout.strip():
            return {"_error": p.stderr.strip()[:400]}
        try:
            d = json.loads(p.stdout)
        except json.JSONDecodeError:
            return {"_error": p.stdout.strip()[:400] or p.stderr.strip()[:400]}
        if d.get("error"):
            return {"_error": d["error"].get("message", str(d["error"]))}
        return d.get("result")


def config_path(given=None):
    return Path(os.path.expanduser(given or os.environ.get("DOGMODE_RELAYTEST_CONFIG") or str(HOME / "nodes.json")))


def load_config(given=None, need_nodes=True):
    """The config, every path in it expanded, a relative one read against the config file's own folder."""
    path = config_path(given)
    raw = {}
    if path.exists():
        raw = json.loads(path.read_text())
    elif need_nodes:
        sys.exit(f"no config at {path}: copy nodes.example.json there and name your nodes (or pass --config)")
    cfg = dict(DEFAULTS, **{k: v for k, v in raw.items() if k != "nodes"})
    for k in ("key_file", "state_file", "record_dir", "out_dir"):
        if cfg[k]:
            p = Path(os.path.expanduser(cfg[k]))
            cfg[k] = p if p.is_absolute() else (path.parent / p).resolve()
    cfg["nodes"] = [Node(n) for n in raw.get("nodes", [])]
    if need_nodes and len(cfg["nodes"]) < 2:
        sys.exit(f"{path} names {len(cfg['nodes'])} node(s); a relay test needs one to send and at least one more to watch")
    cfg["api"] = cfg["api"].rstrip("/")
    cfg["control"] = f"{urlparse(cfg['api']).hostname} (Core policy)"
    return cfg


def http(url, data=None, headers=None, timeout=30):
    req = urllib.request.Request(url, data=data, headers=dict({"User-Agent": "dogmode-relaytest"}, **(headers or {})))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:  # noqa: BLE001
        return 0, str(e)


def api_json(cfg, path):
    code, body = http(cfg["api"] + path)
    try:
        return code, json.loads(body)
    except json.JSONDecodeError:
        return code, body


# ---------------------------------------------------------------- the key

def load_key(cfg, create=False):
    key_file = Path(cfg["key_file"])
    if key_file.exists():
        prv = ec.PrivateKey(bytes.fromhex(key_file.read_text().strip()))
    elif create:
        key_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        secret = os.urandom(32)
        key_file.touch(mode=0o600)
        key_file.write_text(secret.hex() + "\n")
        prv = ec.PrivateKey(secret)
    else:
        sys.exit(f"no key at {key_file}; run `key` first")
    pub = prv.get_public_key()
    spk = script.p2wpkh(pub)
    return prv, pub, spk, spk.address(NETWORKS["main"])


def utxos(cfg, address):
    code, rows = api_json(cfg, f"/address/{address}/utxo")
    if code != 200 or not isinstance(rows, list):
        return []
    return sorted(rows, key=lambda r: -r["value"])


def load_state(cfg):
    try:
        return json.loads(Path(cfg["state_file"]).read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(cfg, d):
    f = Path(cfg["state_file"])
    f.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    f.write_text(json.dumps(d, indent=2) + "\n")


# ---------------------------------------------------------------- building and signing

def pushdata(b):
    n = len(b)
    if n < 0x4c:
        return bytes([n]) + b
    if n <= 0xff:
        return b"\x4c" + bytes([n]) + b
    if n <= 0xffff:
        return b"\x4d" + n.to_bytes(2, "little") + b
    return b"\x4e" + n.to_bytes(4, "little") + b


def op_return(payload):
    return script.Script(b"\x6a" + pushdata(payload))


# The witness shape of the big test. An Umbrel node (its UI writes datacarriersize=100000) refuses a 975 kB OP_RETURN, so the default big transaction carries its bytes
# the way inscriptions do: inside a taproot leaf script that is never executed, spent by script path.
# Witness bytes weigh 1 WU each, so 3.9 MB of them is 975 kvB, the same fee as the OP_RETURN shape.
# Two transactions: a commit (a normal payment to the taproot address, standard everywhere) and the
# reveal (the big one, DOG policy only). The key path stays ours, which is how `reclaim` takes the coin
# back through a Core node if no DOG-policy miner mines the reveal.

def compact_size(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xffffffff:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


CONTENT_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp",
                 ".svg": "image/svg+xml", ".avif": "image/avif", ".txt": "text/plain;charset=utf-8", ".md": "text/markdown",
                 ".html": "text/html;charset=utf-8", ".json": "application/json", ".mp4": "video/mp4", ".mp3": "audio/mpeg"}


def envelope(xonly, payload, content_type=None):
    """<xonly> OP_CHECKSIG OP_FALSE OP_IF [ "ord" 1 <content type> 0 ] <payload in 520-byte pushes> OP_ENDIF

    With a content type this is the ordinals inscription envelope, byte for byte the shape ord indexes:
    if a miner ever includes the reveal, the payload is a real inscription. Without one it is a plain
    data envelope that no indexer will read as anything."""
    sc = b"\x20" + xonly + b"\xac\x00\x63"
    if content_type:
        sc += pushdata(b"ord") + b"\x01\x01" + pushdata(content_type.encode()) + b"\x00"
    for i in range(0, len(payload), 520):
        sc += pushdata(payload[i:i + 520])
    return sc + b"\x68"


def parse_envelope(sc):
    """Read the pushes back out of a tapscript: returns (content_type or None, body bytes) or None."""
    i, pushes, in_env = 0, [], False
    while i < len(sc):
        op = sc[i]; i += 1
        if op == 0x63 and pushes == [b""]:      # OP_FALSE OP_IF
            in_env, pushes = True, []
            continue
        if op == 0x68 and in_env:               # OP_ENDIF
            break
        if op == 0x00:
            data = b""
        elif op <= 0x4b:
            data = sc[i:i + op]; i += op
        elif op == 0x4c:
            n = sc[i]; data = sc[i + 1:i + 1 + n]; i += 1 + n
        elif op == 0x4d:
            n = int.from_bytes(sc[i:i + 2], "little"); data = sc[i + 2:i + 2 + n]; i += 2 + n
        elif op == 0x4e:
            n = int.from_bytes(sc[i:i + 4], "little"); data = sc[i + 4:i + 4 + n]; i += 4 + n
        else:
            pushes = [] if not in_env else pushes   # a non-push opcode outside the envelope resets the OP_FALSE marker
            continue
        pushes.append(data)
    if not in_env:
        return None
    ctype = None
    body_from = 0
    if pushes and pushes[0] == b"ord":
        j = 1
        while j + 1 < len(pushes) and pushes[j] != b"":
            if pushes[j] == b"\x01":
                ctype = pushes[j + 1].decode("utf-8", "replace")
            j += 2
        body_from = j + 1 if j < len(pushes) and pushes[j] == b"" else j
    return ctype, b"".join(pushes[body_from:])


def leaf_hash(sc):
    return hashes.tagged_hash("TapLeaf", b"\xc0" + compact_size(len(sc)) + sc)


def _tagged(tag, msg):
    """BIP340 tagged hash, on hashlib alone, so the check below owes embit nothing."""
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + msg).digest()


def bip341_sighash(tx, index, spent_spks, values, leaf_script=None, leaf_version=0xc0):
    """The BIP341 signature message, hash type DEFAULT, written from the specification.

    WHY THIS EXISTS. embit's `sighash_taproot` takes `ext_flag` as its own argument, defaulting to 0, and
    computes spend_type as `2 * ext_flag + annex`. Pass `script=` for a script path spend and forget
    `ext_flag=1`, as this file did until 2026-09-17, and it appends the tapscript extension while still
    writing a spend_type byte of 0. The result is self consistent, so signing and verifying with embit
    both pass, and every DOG Mode node answers `mempool-script-verify-flag-failed (Invalid Schnorr
    signature)`. Both of our nodes said exactly that on the first live dry run of the big test.

    So the kit signs THIS message and only uses embit's as a cross check that has to agree."""
    # embit holds a txid in DISPLAY order and reverses it when it serializes; the message wants the
    # internal order, so reverse it here too. Getting this wrong is invisible offline: the hash simply
    # differs, and the node is the only thing that tells you.
    prevouts = b"".join(bytes(reversed(i.txid)) + i.vout.to_bytes(4, "little") for i in tx.vin)
    amounts = b"".join(v.to_bytes(8, "little") for v in values)
    spks = b"".join(compact_size(len(s.data)) + s.data for s in spent_spks)
    sequences = b"".join(i.sequence.to_bytes(4, "little") for i in tx.vin)
    outputs = b"".join(o.value.to_bytes(8, "little") + compact_size(len(o.script_pubkey.data)) + o.script_pubkey.data
                       for o in tx.vout)
    msg = b"\x00"                                   # hash type: DEFAULT
    msg += tx.version.to_bytes(4, "little")
    msg += tx.locktime.to_bytes(4, "little")
    msg += hashlib.sha256(prevouts).digest()
    msg += hashlib.sha256(amounts).digest()
    msg += hashlib.sha256(spks).digest()
    msg += hashlib.sha256(sequences).digest()
    msg += hashlib.sha256(outputs).digest()
    msg += bytes([2 if leaf_script is not None else 0])   # spend_type: ext_flag 1 for tapscript, no annex
    msg += index.to_bytes(4, "little")
    if leaf_script is not None:
        msg += _tagged("TapLeaf", bytes([leaf_version]) + compact_size(len(leaf_script)) + leaf_script)
        msg += b"\x00"                              # key version
        msg += b"\xff\xff\xff\xff"                  # no OP_CODESEPARATOR
    return _tagged("TapSighash", b"\x00" + msg)


def taproot_from_leaf(pub, leaf):
    """(scriptPubKey, control block) for a single-leaf tree with `pub` as the internal key."""
    x = pub.xonly()
    tweak = hashes.tagged_hash("TapTweak", x + leaf)
    point = secp256k1.ec_pubkey_add(secp256k1.ec_pubkey_parse(b"\x02" + x), tweak)
    sec = secp256k1.ec_pubkey_serialize(point)
    return script.Script(b"\x51\x20" + sec[1:33]), bytes([0xc0 | (sec[0] & 1)]) + x


def build_reveal(prv, pub, wpkh_spk, commit_txid, vout, value, sc, feerate):
    leaf = leaf_hash(sc)
    tr_spk, control = taproot_from_leaf(pub, leaf)
    vin = TransactionInput(bytes.fromhex(commit_txid), vout, sequence=0xFFFFFFFD)
    out = TransactionOutput(0, wpkh_spk)
    tx = Transaction(version=2, vin=[vin], vout=[out], locktime=0)
    for _ in range(2):
        tx.clear_cache()
        # Sign the message written from BIP341 itself, and make embit agree with `ext_flag=1`. Without
        # that argument embit writes spend_type 0 for a script path spend and every node refuses the
        # signature (bip341_sighash's docstring has the whole scar).
        h = bip341_sighash(tx, 0, [tr_spk], [value], leaf_script=sc)
        h_embit = tx.sighash_taproot(0, [tr_spk], [value], sighash=0, ext_flag=1,
                                     script=script.Script(sc), leaf_version=0xc0)
        if h != h_embit:
            raise SystemExit("the BIP341 message and embit's disagree on the reveal; refusing to sign blind")
        sig = prv.schnorr_sign(h).serialize()
        tx.vin[0].witness = script.Witness([sig, sc, control])
        _, _, weight, vsize = sizes(tx)
        fee = int(vsize * feerate) if vsize * feerate == int(vsize * feerate) else int(vsize * feerate) + 1
        out.value = max(value - fee, 0)   # clamped: the fit loop calls this with a guessed value first
    return tx, fee, weight, vsize, leaf, tr_spk


def fit_witness(prv, pub, wpkh_spk, utxo, payload, feerate, content_type=None):
    """Trim the payload until the reveal weighs at most MAX_STANDARD_TX_WEIGHT, then build the commit
    that funds it. A file with a content type is never trimmed: it fits whole or the run stops.
    Returns (commit, reveal, leaf, payload_len, reveal_fee, reveal_weight, reveal_vsize)."""
    x = pub.xonly()
    n = min(len(payload), MAX_STANDARD_TX_WEIGHT)
    placeholder = "00" * 32
    while True:
        sc = envelope(x, payload[:n], content_type)
        reveal, fee, weight, vsize, leaf, tr_spk = build_reveal(prv, pub, wpkh_spk, placeholder, 0, fee_guess(n, feerate) + 1000, sc, feerate)
        over = weight - MAX_STANDARD_TX_WEIGHT
        if over <= 0:
            break
        if content_type:
            raise SystemExit(f"the file is {len(payload):,} bytes and weighs {weight:,} WU in the reveal; the most this shape carries whole is about {len(payload) - over:,} bytes")
        n -= max(over, 1)
        if n <= 0:
            raise SystemExit("could not fit the payload")
    # the commit pays the reveal's fee plus 1,000 sats that come back to the key in the reveal's output
    commit, cfee, _, _ = build(prv, pub, wpkh_spk, utxo, [TransactionOutput(fee + 1000, tr_spk)], feerate)
    reveal, fee2, weight, vsize, leaf, _ = build_reveal(prv, pub, wpkh_spk, commit.txid().hex(), 0, fee + 1000, sc, feerate)
    assert fee2 == fee and reveal.vout[0].value == 1000, (fee, fee2, reveal.vout[0].value)
    return commit, reveal, leaf, n, fee, weight, vsize


def fee_guess(payload_len, feerate):
    # each 520-byte chunk is 523 script bytes (OP_PUSHDATA2, two length bytes, the chunk); a generous guess
    return int((payload_len * 523 / 520 + 4000) / 4 * feerate) + 1


def build_keypath_reclaim(prv, pub, wpkh_spk, commit_txid, vout, value, leaf, feerate):
    """Spend the commit's taproot output by key path, back to the key: the reclaim for the witness shape."""
    tr_spk, _ = taproot_from_leaf(pub, leaf)
    tweaked = prv.taproot_tweak(leaf)
    vin = TransactionInput(bytes.fromhex(commit_txid), vout, sequence=0xFFFFFFFD)
    out = TransactionOutput(0, wpkh_spk)
    tx = Transaction(version=2, vin=[vin], vout=[out], locktime=0)
    for _ in range(2):
        tx.clear_cache()
        h = bip341_sighash(tx, 0, [tr_spk], [value])          # key path: spend_type 0, no extension
        h_embit = tx.sighash_taproot(0, [tr_spk], [value], sighash=0)
        if h != h_embit:
            raise SystemExit("the BIP341 message and embit's disagree on the reclaim; refusing to sign blind")
        tx.vin[0].witness = script.Witness([tweaked.schnorr_sign(h).serialize()])
        _, _, weight, vsize = sizes(tx)
        fee = int(vsize * feerate) if vsize * feerate == int(vsize * feerate) else int(vsize * feerate) + 1
        out.value = value - fee
    if out.value < 546:
        raise SystemExit(f"the commit output holds {value} sats, not enough to reclaim at {feerate} sat/vB")
    return tx, fee, weight, vsize


def sizes(tx):
    """(base size, total size, weight, vsize) the way Core counts them."""
    total = len(tx.serialize())
    saved = [vin.witness for vin in tx.vin]
    for vin in tx.vin:
        vin.witness = script.Witness([])
    base = len(tx.serialize())
    for vin, w in zip(tx.vin, saved):
        vin.witness = w
    weight = base * 3 + total
    return base, total, weight, (weight + 3) // 4


def build(prv, pub, spk, utxo, outputs, feerate):
    """One P2WPKH input, the given outputs, change back to the key, fee = ceil(vsize * feerate)."""
    txid, vout, value = utxo["txid"], utxo["vout"], utxo["value"]
    vin = TransactionInput(bytes.fromhex(txid), vout, sequence=0xFFFFFFFD)
    change = TransactionOutput(0, spk)
    tx = Transaction(version=2, vin=[vin], vout=list(outputs) + [change], locktime=0)
    # sign once with a placeholder change to learn the size, then set the real change and sign again
    for _ in range(2):
        sign(tx, prv, pub, value)
        _, _, weight, vsize = sizes(tx)
        fee = -(-vsize * feerate // 1)  # ceil
        fee = int(fee) if fee == int(fee) else int(fee) + 1
        spent = sum(o.value for o in outputs)
        # Checked INSIDE the loop: a negative change value is serialized by the second signing pass,
        # and embit raises OverflowError there, which says nothing about what is short. 2026-09-17.
        if value - spent - fee < 1000:
            raise SystemExit(f"the coin {txid}:{vout} holds {value:,} sats; this transaction needs {spent + fee:,} "
                             f"plus 1,000 of change, so it is {spent + fee + 1000 - value:,} sats short")
        change.value = value - spent - fee
    return tx, fee, weight, vsize


def sign(tx, prv, pub, value, index=0):
    sc = script.p2pkh_from_p2wpkh(script.p2wpkh(pub))
    tx.clear_cache()   # embit caches the outputs digest; a second signing pass after the change is set must not reuse it
    h = tx.sighash_segwit(index, sc, value, sighash=SIGHASH.ALL)
    sig = prv.sign(h)
    tx.vin[index].witness = script.Witness([sig.serialize() + bytes([SIGHASH.ALL]), pub.sec()])


def build_sweep(prv, pub, coins, dest_spk, feerate):
    """Every coin given, one output to an address outside this key, fee = ceil(vsize * feerate).

    This is how the money leaves the throwaway key for your own wallet. `reclaim` only ever brings a
    coin back to the key itself, which is not the same thing as having it back."""
    total = sum(c["value"] for c in coins)
    vin = [TransactionInput(bytes.fromhex(c["txid"]), c["vout"], sequence=0xFFFFFFFD) for c in coins]
    out = TransactionOutput(0, dest_spk)
    tx = Transaction(version=2, vin=vin, vout=[out], locktime=0)
    for _ in range(2):
        for i, c in enumerate(coins):
            sign(tx, prv, pub, c["value"], index=i)
        _, _, weight, vsize = sizes(tx)
        fee = int(vsize * feerate) if vsize * feerate == int(vsize * feerate) else int(vsize * feerate) + 1
        if total - fee < 546:
            raise SystemExit(f"{len(coins)} coin(s) hold {total:,} sats; a sweep at {feerate} sat/vB costs {fee:,} "
                             f"and what is left would be dust")
        out.value = total - fee
    return tx, fee, weight, vsize


def big_payload(path):
    if path:
        return Path(path).read_bytes()
    head = (f"DOG Mode relay test, {utc()}. A 3,900,000 weight-unit transaction, the largest a DOG Mode node "
            f"relays, sent from one DOG Mode node to be read in another. Bitcoin Core policy stops at 400,000. "
            f"Relay policy is a choice. https://seed.dogofbitcoin.org\n").encode()
    line = b"Relay policy is a choice.\n"
    return head + line * (4_000_000 // len(line))   # more than any shape can carry; fit_* trims it to the limit


def fit_big(prv, pub, spk, utxo, payload, feerate):
    """Trim the payload until the transaction weighs at most MAX_STANDARD_TX_WEIGHT and the OP_RETURN
    script is at most MAX_DATACARRIER bytes. Returns (tx, fee, weight, vsize, payload_len)."""
    n = min(len(payload), MAX_DATACARRIER - 6)
    while True:
        out = TransactionOutput(0, op_return(payload[:n]))
        tx, fee, weight, vsize = build(prv, pub, spk, utxo, [out], feerate)
        over = max(weight - MAX_STANDARD_TX_WEIGHT, 0)
        if over == 0 and len(out.script_pubkey.data) <= MAX_DATACARRIER:
            return tx, fee, weight, vsize, n
        n -= max(over // 4, 1)
        if n <= 0:
            raise SystemExit("could not fit the payload")


def preflight(prv, pub, spk, path, feerate, fund, content_type=None):
    """OFFLINE, before a single sat is sent: build the whole big test against a hypothetical coin and
    prove it. No node, no network, nothing signed against a real coin.

    It answers the two questions that funding rests on. Does the file fit whole under the 3,900,000 WU
    limit, and can the money come back by key path if no miner takes the reveal. Every check is made on
    freshly parsed bytes, never on the objects that did the signing (the embit cache scar).
    Returns (ok, rows, numbers)."""
    payload = Path(path).read_bytes()
    ctype = content_type or CONTENT_TYPES.get(Path(path).suffix.lower())
    if not ctype:
        raise SystemExit(f"no content type known for {Path(path).suffix}; pass --content-type")
    digest = hashlib.sha256(payload).hexdigest()
    utxo = {"txid": "ab" * 32, "vout": 0, "value": fund}
    commit, reveal, leaf, n, fee, weight, vsize = fit_witness(prv, pub, spk, utxo, payload, feerate, ctype)
    cfee = utxo["value"] - sum(o.value for o in commit.vout)
    _, _, _, cvsize = sizes(commit)

    parsed = Transaction.parse(reveal.serialize())
    items = parsed.vin[0].witness.items
    env = parse_envelope(items[1]) if len(items) >= 3 else None
    tr_spk, _ = taproot_from_leaf(pub, leaf_hash(items[1]))
    parsed.clear_cache()
    rh = bip341_sighash(parsed, 0, [tr_spk], [commit.vout[0].value], leaf_script=items[1])
    rh_embit = parsed.sighash_taproot(0, [tr_spk], [commit.vout[0].value], sighash=0, ext_flag=1,
                                      script=script.Script(items[1]), leaf_version=0xc0)
    reclaim, rfee, _, rvsize = build_keypath_reclaim(prv, pub, spk, commit.txid().hex(), 0,
                                                     commit.vout[0].value, leaf, max(feerate, 2.0))
    rparsed = Transaction.parse(reclaim.serialize())
    rparsed.clear_cache()
    kh = bip341_sighash(rparsed, 0, [tr_spk], [commit.vout[0].value])
    kh_embit = rparsed.sighash_taproot(0, [tr_spk], [commit.vout[0].value], sighash=0)

    rows = [
        ("the file fits whole, untrimmed", n == len(payload)),
        ("the reveal is under the DOG Mode limit", weight <= MAX_STANDARD_TX_WEIGHT),
        ("the reveal is over Core's limit, which is the point", weight > 400_000),
        ("the file reads back out of the reveal's own witness",
         env is not None and hashlib.sha256(env[1]).hexdigest() == digest),
        ("the content type in the envelope is the file's", env is not None and env[0] == ctype),
        ("the leaf derived from the witness equals the one built", leaf_hash(items[1]) == leaf),
        ("the commit pays exactly the address that leaf makes", commit.vout[0].script_pubkey.data == tr_spk.data),
        ("the signature message matches BIP341, computed here and by embit",
         rh == rh_embit and kh == kh_embit),
        ("the reveal's signature verifies on the serialized bytes",
         ec.PublicKey.from_xonly(pub.xonly()).schnorr_verify(ec.SchnorrSig.parse(items[0]), rh)),
        ("THE MONEY COMES BACK: the key path reclaim verifies",
         ec.PublicKey.from_xonly(tr_spk.data[2:34]).schnorr_verify(
             ec.SchnorrSig.parse(rparsed.vin[0].witness.items[0]), kh)),
        ("the reclaim pays the key's own address", reclaim.vout[0].script_pubkey.data == spk.data),
        ("the reveal's output comes back to the key", reveal.vout[0].script_pubkey.data == spk.data),
    ]
    numbers = {"payload": n, "sha256": digest, "content_type": ctype, "weight": weight, "vsize": vsize,
               "reveal_fee": fee, "commit_vsize": cvsize, "commit_fee": cfee,
               "commit_pays": commit.vout[0].value, "needs": commit.vout[0].value + cfee + 1000,
               "change": commit.vout[1].value, "reveal_out": reveal.vout[0].value,
               "reclaim_vsize": rvsize, "reclaim_fee": rfee, "reclaim_back": reclaim.vout[0].value}
    return all(ok for _, ok in rows), rows, numbers


# ---------------------------------------------------------------- readings

def node_summary(node):
    net = node.rpc("getnetworkinfo")
    if not isinstance(net, dict) or "_error" in net:
        return f"{node.name}: UNREADABLE {net}"
    chain = node.rpc("getblockchaininfo")
    mp = node.rpc("getmempoolinfo")
    peers = node.rpc("getpeerinfo")
    dogs = [p for p in peers if int(p["services"], 16) & DOG_BIT] if isinstance(peers, list) else []
    dogconn = sum(1 for p in peers if p.get("connection_type") == "dog") if isinstance(peers, list) else 0
    return (f"{node.name}: {net['subversion']} services {net['localservicesnames']} height {chain.get('blocks')} "
            f"peers in {net['connections_in']} out {net['connections_out']} | DOG-bit peers {len(dogs)} "
            f"(outbound dog slots filled {dogconn}) | mempool {mp.get('size')} txs, min fee {mp.get('mempoolminfee')} BTC/kvB, "
            f"datacarrier {mp.get('maxdatacarriersize')}")


def in_mempool(r):
    return isinstance(r, dict) and "_error" not in r and bool(r)


def where(cfg, txid):
    out = {}
    for node in cfg["nodes"]:
        r = node.rpc("getmempoolentry", txid)
        out[node.name] = "in mempool" if in_mempool(r) else f"absent ({r.get('_error') if isinstance(r, dict) else r})"
    code, _ = api_json(cfg, f"/tx/{txid}")     # the full transaction, never /status (the scar in the docstring)
    out[cfg["control"]] = "HAS IT" if code == 200 else f"absent (HTTP {code})"
    return out


def price_usd(cfg):
    code, d = api_json(cfg, "/v1/prices")
    return d.get("USD") if code == 200 and isinstance(d, dict) else None


def usd(sats, px):
    return f"${sats / 1e8 * px:,.2f}" if px else "?"


def relay_rate(cfg, given):
    """reclaim and sweep: the control's fastest fee, never under 2 sat/vB, unless --feerate says otherwise."""
    if given is not None:
        return given
    code, fees = api_json(cfg, "/v1/fees/recommended")
    return max(float(fees.get("fastestFee", 2)) if code == 200 and isinstance(fees, dict) else 2.0, 2.0)


# ---------------------------------------------------------------- the runs

def dry_run(cfg, label, hexes, extra=""):
    """testmempoolaccept on every node, for one transaction or a package (the commit and its reveal)."""
    for node in cfg["nodes"]:
        r = node.rpc("testmempoolaccept", hexes)
        if isinstance(r, list) and r:
            print(f"  {node.name} testmempoolaccept: " + "; ".join(
                f"allowed={x.get('allowed')} {x.get('reject-reason', '')}".rstrip() for x in r) + extra)
        else:
            print(f"  {node.name} testmempoolaccept: {r}")


def send_and_watch(cfg, label, tx, hexs, fee, weight, vsize, utxo, note):
    sender, watchers = cfg["nodes"][0], cfg["nodes"][1:]
    txid = tx.txid().hex()
    t0 = time.time()
    r = sender.rpc("sendrawtransaction", hexs)
    sent_at = utc()
    if r != txid:
        print(f"{sender.name} refused it: {r}")
        return
    print(f"{sender.name} accepted {txid} at {sent_at}")
    seen = {}
    for _ in range(90):
        for node in watchers:
            if node.name not in seen and in_mempool(node.rpc("getmempoolentry", txid)):
                seen[node.name] = round(time.time() - t0, 1)
        if len(seen) == len(watchers):
            break
        time.sleep(2)
    for node in watchers:
        print(f"{node.name}: " + (f"in mempool after {seen[node.name]} s (the poll's clock; getmempoolentry's own "
                                 f"'time' is the node's)" if node.name in seen else "NOT seen in 180 s"))
    time.sleep(20)
    w = where(cfg, txid)
    print("where it is now:", json.dumps(w))
    st = load_state(cfg)
    st.setdefault("runs", []).append({"label": label, "txid": txid, "input": f"{utxo['txid']}:{utxo['vout']}",
                                      "input_value": utxo["value"], "fee": fee, "weight": weight, "vsize": vsize,
                                      "sent_at": sent_at, "seen_after": seen, "where": w})
    save_state(cfg, st)
    if cfg["record_dir"]:
        path = Path(cfg["record_dir"]) / f"{datetime.now(timezone.utc):%Y-%m-%d}-dogmode-relay-test-{label}.md"
        with path.open("a") as fh:
            fh.write(f"# DOG Mode relay test, {label}: {note}\n\n")
            fh.write(f"Sent {sent_at} from {sender.name} (`sendrawtransaction`), read on "
                     f"{', '.join(n.name for n in watchers)} (`getmempoolentry`) and on {cfg['control']}.\n\n")
            fh.write(f"| | |\n|---|---|\n| txid | `{txid}` |\n| input | `{utxo['txid']}:{utxo['vout']}` ({utxo['value']:,} sats) |\n")
            fh.write(f"| weight | {weight:,} WU |\n| vsize | {vsize:,} vB |\n| fee | {fee:,} sats ({fee / vsize:.3f} sat/vB) |\n")
            for node in watchers:
                fh.write(f"| seen on {node.name} after | {str(seen[node.name]) + ' s' if node.name in seen else 'not within 180 s'} |\n")
            for k, v in w.items():
                fh.write(f"| {k} | {v} |\n")
            fh.write(f"\nRe-check any time: `relaytest.py watch {txid}`\n\n")
        print(f"record appended: {path}")


def broadcast(cfg, st, label, tx, spent, input_value, fee, weight, vsize):
    """reclaim and sweep go out through the control's API, which relays to Core-policy nodes."""
    code, body = http(cfg["api"] + "/tx", data=tx.serialize().hex().encode(), headers={"Content-Type": "text/plain"})
    print(f"{cfg['control']} POST /tx: HTTP {code} {body[:120]}")
    st.setdefault("runs", []).append({"label": label, "txid": tx.txid().hex(), "input": spent, "input_value": input_value,
                                      "fee": fee, "weight": weight, "vsize": vsize, "sent_at": utc(),
                                      "seen_after": {}, "where": {cfg["control"]: f"HTTP {code}"}})
    return code


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("cmd", choices=["key", "status", "preflight", "dust", "big", "reclaim", "sweep", "watch", "decode"])
    ap.add_argument("txid", nargs="?", help="watch and decode: the txid. sweep: the address to send everything to")
    ap.add_argument("--config", help="the node config (default: DOGMODE_RELAYTEST_CONFIG, or ~/.dogmode-relaytest/nodes.json)")
    ap.add_argument("--go", action="store_true", help="send it (default is a dry run that sends nothing)")
    ap.add_argument("--feerate", type=float, default=None,
                    help="sat/vB (default 1.0 for dust and big; reclaim and sweep use the control's fastest, never under 2)")
    ap.add_argument("--fund", type=int, default=150_000, help="preflight: the made up coin to build against (default 150,000)")
    ap.add_argument("--payload", help="big: a file whose bytes ride in the transaction as plain data (default: a text banner, trimmed to fit)")
    ap.add_argument("--inscribe", help="big: a file to carry as a real ordinals inscription (content type from its extension); never trimmed")
    ap.add_argument("--content-type", help="big --inscribe: override the content type")
    ap.add_argument("--expect", help="decode: the original file, to compare hashes")
    ap.add_argument("--mode", choices=["witness", "opreturn"], default="witness",
                    help="big: witness (a taproot reveal, passes every DOG node; default) or opreturn (one 975 kB OP_RETURN; refused by nodes with datacarriersize=100000, which is every Umbrel)")
    a = ap.parse_args()
    rate = a.feerate if a.feerate is not None else 1.0   # dust and big; reclaim and sweep resolve their own
    cfg = load_config(a.config, need_nodes=a.cmd not in ("key", "preflight"))

    if a.cmd == "preflight":
        # Offline on purpose: no node, no price, no API. This is what gets run BEFORE funding.
        prv, pub, spk, addr = load_key(cfg)
        src = a.inscribe or a.payload
        if not src:
            sys.exit("preflight needs the file: preflight --inscribe FILE")
        ok, rows, m = preflight(prv, pub, spk, src, rate, a.fund, a.content_type)
        print(f"preflight, offline, {utc()}")
        print(f"  file      {src}")
        print(f"  payload   {m['payload']:,} bytes, {m['content_type']}, sha256 {m['sha256']}")
        print(f"  reveal    {m['weight']:,} WU ({m['weight'] / MAX_STANDARD_TX_WEIGHT:.1%} of DOG Mode's limit, "
              f"{m['weight'] / 400_000:.1f} times Core's), {m['vsize']:,} vB, fee {m['reveal_fee']:,} sats at {rate} sat/vB")
        print(f"  commit    {m['commit_vsize']} vB, fee {m['commit_fee']:,} sats, pays {m['commit_pays']:,} sats to the leaf address")
        print(f"  funding   ONE CONFIRMED coin of at least {m['needs']:,} sats; from {a.fund:,} the change back is {m['change']:,}")
        print(f"  no miner takes it: the reclaim is {m['reclaim_vsize']} vB, costs {m['reclaim_fee']:,} sats and returns {m['reclaim_back']:,} sats to the key")
        print(f"  one does:          {m['reveal_fee']:,} sats go to it as fee and the inscription lands on the {m['reveal_out']:,} sat output at {addr}")
        for label, good in rows:
            print(f"  [{'PASS' if good else 'FAIL'}] {label}")
        print(f"{len(rows)} checks, all pass" if ok else "SOMETHING FAILED. Do not fund anything.")
        sys.exit(0 if ok else 1)

    if a.cmd == "key":
        prv, pub, spk, addr = load_key(cfg, create=True)
        print(f"throwaway key: {cfg['key_file']} (mode 600, this machine only)")
        print(f"address (P2WPKH, mainnet): {addr}")
        u = utxos(cfg, addr)
        print(f"coins: {sum(r['value'] for r in u):,} sats in {len(u)} output(s)" if u else "coins: none yet; send the test amount here")
        return

    if a.cmd == "watch":
        if not a.txid:
            sys.exit("watch needs a txid")
        print(json.dumps(where(cfg, a.txid), indent=2))
        return

    if a.cmd == "decode":
        # The proof that a DOG Mode node holds the bytes: each node hands the raw transaction back out of
        # its own mempool, the envelope is read, the file is written and hashed.
        if not a.txid:
            sys.exit("decode needs a txid")
        want = hashlib.sha256(Path(a.expect).read_bytes()).hexdigest() if a.expect else None
        for node in cfg["nodes"]:
            raw = node.rpc("getrawtransaction", a.txid)
            if not isinstance(raw, str):
                print(f"{node.name}: no transaction ({raw})")
                continue
            tx = Transaction.parse(bytes.fromhex(raw))
            items = tx.vin[0].witness.items
            env = parse_envelope(items[1]) if len(items) >= 3 else None
            if not env:
                print(f"{node.name}: {len(raw) // 2:,} bytes, no envelope in input 0")
                continue
            ctype, body = env
            digest = hashlib.sha256(body).hexdigest()
            ext = next((k for k, v in CONTENT_TYPES.items() if v == ctype), ".bin")
            out = Path(cfg["out_dir"]) / f"{a.txid[:16]}-from-{re.sub(r'[^A-Za-z0-9_.-]', '_', node.name)}{ext}"
            out.write_bytes(body)
            print(f"{node.name}: {len(raw) // 2:,} bytes from its mempool; envelope {ctype or 'plain data'}, {len(body):,} bytes, sha256 {digest}; written {out}" + (f"; matches the original: {digest == want}" if want else ""))
        return

    prv, pub, spk, addr = load_key(cfg)
    px = price_usd(cfg)

    if a.cmd == "status":
        print(utc())
        for node in cfg["nodes"]:
            print(node_summary(node))
        u = utxos(cfg, addr)
        print(f"key {addr}: {sum(r['value'] for r in u):,} sats in {len(u)} output(s)" + ("" if u else " (unfunded)"))
        print(f"BTC {usd(100_000_000, px)}; at {rate} sat/vB the dust test costs about {usd(140 * rate, px)} of fee,"
              f" and the big test puts {int(962_000 * rate):,} sats ({usd(962_000 * rate, px)}) at risk, only if a miner includes the reveal before `reclaim` confirms")
        for r in load_state(cfg).get("runs", []):
            seen = r.get("seen_after") or ({"umbrel": r["umbrel_seconds"]} if r.get("umbrel_seconds") else {})
            print(f"run {r['label']} {r['sent_at']}: {r['txid']}" + "".join(f" | {k} after {v} s" for k, v in seen.items()))
        return

    u = utxos(cfg, addr)
    confirmed = [r for r in u if r.get("status", {}).get("confirmed")]
    if a.cmd in ("dust", "big") and not confirmed:
        sys.exit(f"no confirmed coin on {addr}; fund it and wait one confirmation ({len(u)} unconfirmed)")
    sender = cfg["nodes"][0].name

    if a.cmd == "dust":
        utxo = confirmed[0]
        out = TransactionOutput(1, spk)     # 1 sat, to ourselves: dust for Core (294 sats for P2WPKH), fine for DOG Mode
        tx, fee, weight, vsize = build(prv, pub, spk, utxo, [out], rate)
        hexs = tx.serialize().hex()
        print(f"[dust] txid {tx.txid().hex()}")
        print(f"  weight {weight:,} WU, vsize {vsize:,} vB, fee {fee:,} sats ({fee / vsize:.3f} sat/vB); output 0 pays 1 sat to {addr}")
        dry_run(cfg, "dust", [hexs])
        if a.go:
            send_and_watch(cfg, "dust", tx, hexs, fee, weight, vsize, utxo, "a 1 sat output relayed between DOG Mode nodes")
        else:
            print("dry run only; add --go to send")
        return

    if a.cmd == "big" and a.mode == "opreturn":
        utxo = confirmed[0]
        payload = big_payload(a.payload)
        tx, fee, weight, vsize, n = fit_big(prv, pub, spk, utxo, payload, rate)
        hexs = tx.serialize().hex()
        print(f"[big, OP_RETURN shape] txid {tx.txid().hex()}")
        print(f"  weight {weight:,} WU (DOG limit {MAX_STANDARD_TX_WEIGHT:,}, Core 400,000), vsize {vsize:,} vB, fee {fee:,} sats; "
              f"OP_RETURN carries {n:,} bytes; {usd(fee, px)} at risk only if a DOG-policy miner mines it")
        dry_run(cfg, "big", [hexs])
        if a.go:
            send_and_watch(cfg, "big", tx, hexs, fee, weight, vsize, utxo, "a 3,900,000 WU transaction (OP_RETURN shape) relayed between DOG Mode nodes")
            print("next: `reclaim --go` once the dog mempools have shown it, to take the coin back through a Core node")
        else:
            print("dry run only; add --go to send")
        return

    if a.cmd == "big":
        utxo = confirmed[0]
        ctype = None
        if a.inscribe:
            payload = Path(a.inscribe).read_bytes()
            ctype = a.content_type or CONTENT_TYPES.get(Path(a.inscribe).suffix.lower())
            if not ctype:
                sys.exit(f"no content type known for {Path(a.inscribe).suffix}; pass --content-type")
        else:
            payload = big_payload(a.payload)
        commit, reveal, leaf, n, fee, weight, vsize = fit_witness(prv, pub, spk, utxo, payload, rate, ctype)
        hex_c, hex_r = commit.serialize().hex(), reveal.serialize().hex()
        _, _, cw, cv = sizes(commit)
        what = f"a real ordinals inscription, {ctype}, {n:,} bytes, sha256 {hashlib.sha256(payload).hexdigest()[:16]}" if ctype else f"{n:,} bytes of plain data"
        print(f"[big, witness shape] commit {commit.txid().hex()}: {cv} vB, pays {commit.vout[0].value:,} sats to the taproot leaf address, standard everywhere")
        print(f"[big, witness shape] reveal {reveal.txid().hex()} carrying {what}")
        print(f"  weight {weight:,} WU (DOG limit {MAX_STANDARD_TX_WEIGHT:,}, Core 400,000), vsize {vsize:,} vB, {len(hex_r) // 2:,} bytes, fee {fee:,} sats ({fee / vsize:.3f} sat/vB); {usd(fee, px)} at risk only if a DOG-policy miner mines it")
        dry_run(cfg, "big", [hex_c, hex_r], extra="  (commit; reveal)")
        if a.go:
            r = cfg["nodes"][0].rpc("sendrawtransaction", hex_c)
            if r != commit.txid().hex():
                print(f"{sender} refused the commit: {r}")
                return
            print(f"{sender} accepted the commit {r}")
            st = load_state(cfg)
            st["last_commit"] = {"txid": commit.txid().hex(), "vout": 0, "value": commit.vout[0].value, "leaf": leaf.hex(), "sent_at": utc()}
            save_state(cfg, st)
            send_and_watch(cfg, "big", reveal, hex_r, fee, weight, vsize, {"txid": commit.txid().hex(), "vout": 0, "value": commit.vout[0].value},
                           "a 3,900,000 WU transaction (taproot reveal, witness shape) relayed between DOG Mode nodes")
            print("next: `reclaim --go` once the dog mempools have shown it, to take the coin back by key path through a Core node")
        else:
            print("dry run only; add --go to send")
        return

    if a.cmd == "reclaim":
        st = load_state(cfg)
        rate = relay_rate(cfg, a.feerate)
        lc = st.get("last_commit")
        if lc:
            tx, fee, weight, vsize = build_keypath_reclaim(prv, pub, spk, lc["txid"], lc["vout"], lc["value"], bytes.fromhex(lc["leaf"]), rate)
            spent = f"{lc['txid']}:{lc['vout']}"
        else:
            # the dust test and the OP_RETURN-shaped big test are both non-standard for Core, so their coin sits
            # in dog mempools until it is spent through a Core node; this is that spend. Only an input Core still
            # sees as an unspent coin AT THIS KEY's address: without that check the fallback once picked the
            # witness run, whose input is the commit's taproot output, and signed it as P2WPKH. 2026-09-17.
            live = {f"{r['txid']}:{r['vout']}" for r in utxos(cfg, addr)}
            runs = [r for r in st.get("runs", []) if r["label"] in ("big", "dust") and r.get("input_value") and r["input"] in live]
            if not runs:
                sys.exit("no dust or big run whose input is still an unspent coin at this key; nothing to reclaim "
                         "(to move what is there to your own wallet, use `sweep ADDRESS`)")
            last = runs[-1]
            txid, vout = last["input"].split(":")
            tx, fee, weight, vsize = build(prv, pub, spk, {"txid": txid, "vout": int(vout), "value": last["input_value"]}, [], rate)
            spent = last["input"]
        print(f"[reclaim] txid {tx.txid().hex()} spends {spent} back to {addr}, {vsize} vB at {rate} sat/vB = {fee:,} sats, "
              f"through {cfg['control']} (the dog nodes keep the big one until this confirms)")
        if a.go:
            if broadcast(cfg, st, "reclaim", tx, spent, None, fee, weight, vsize) == 200:
                st.pop("last_commit", None)
            save_state(cfg, st)
        else:
            print("dry run only; add --go to send")
        return

    if a.cmd == "sweep":
        # `reclaim` only ever moves a coin back to the test key. This is how the money leaves it.
        dest = a.txid
        if not dest:
            sys.exit("sweep needs the address to send everything to: sweep bc1...")
        if dest == addr:
            sys.exit("that is the test key's own address; a sweep sends the money OUT of this key")
        try:
            dest_spk = script.address_to_scriptpubkey(dest)
        except Exception as e:   # noqa: BLE001
            sys.exit(f"not an address this tool can parse: {dest} ({e})")
        u = utxos(cfg, addr)
        coins = [r for r in u if r.get("status", {}).get("confirmed")]
        if not coins:
            sys.exit(f"no confirmed coin at {addr} to sweep ({len(u)} unconfirmed; wait for a block)")
        rate = relay_rate(cfg, a.feerate)
        tx, fee, weight, vsize = build_sweep(prv, pub, coins, dest_spk, rate)
        st = load_state(cfg)
        held = {r["input"] for r in st.get("runs", []) if r["label"] in ("dust", "big")}
        print(f"[sweep] {len(coins)} confirmed coin(s), {sum(c['value'] for c in coins):,} sats, out of {addr}")
        for c in coins:
            mark = "  (a test transaction in the dog mempools spends this one; sweeping it replaces that test)" if f"{c['txid']}:{c['vout']}" in held else ""
            print(f"  {c['txid']}:{c['vout']}  {c['value']:,} sats{mark}")
        print(f"[sweep] txid {tx.txid().hex()} pays {tx.vout[0].value:,} sats to {dest}, {vsize} vB at {rate} sat/vB = {fee:,} sats of fee, through {cfg['control']}")
        if a.go:
            broadcast(cfg, st, "sweep", tx, ",".join(f"{c['txid']}:{c['vout']}" for c in coins), sum(c["value"] for c in coins), fee, weight, vsize)
            save_state(cfg, st)
        else:
            print("dry run only; add --go to send")
        return


if __name__ == "__main__":
    main()
