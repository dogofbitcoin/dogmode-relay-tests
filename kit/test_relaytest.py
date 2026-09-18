"""The relay test kit builds transactions that carry real money, so its shapes are tested offline.

Nothing here touches a node, an API or the network, and nothing is broadcast. The tests make their own keys, so
they pass on a machine that has never run the kit. Run with the python that has embit:

    ~/.venvs/dogmode/bin/python -m unittest discover -s . -p "test_*.py"

What is pinned here, each of it paid for on mainnet on 2026-09-17:
  1. an underfunded coin must SAY what is short, not raise OverflowError deep inside embit's serializer
  2. the payload has to read back out of the reveal's own serialized witness, byte for byte
  3. the key path reclaim has to verify, because that signature is the only way the money comes back
  4. the sweep's signatures have to verify on every input, because that is how the money leaves the key
  5. the BIP341 message is the one a node computes, not the one embit computes without ext_flag
And since the kit reaches any node through a config: a call's arguments go on stdin, never on a command line.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True

# Borrow ~/.venvs/dogmode's packages when this interpreter has no embit of its own, and skip when neither does.
for _sp in sorted((Path.home() / ".venvs" / "dogmode" / "lib").glob("python3.*/site-packages")):
    sys.path.append(str(_sp))

try:
    import relaytest as kit
    from embit import ec, script
    from embit.transaction import SIGHASH, Transaction
    MISSING = ""
except (ImportError, SystemExit) as e:  # the kit calls sys.exit when embit is absent
    MISSING = str(e) or "embit is not importable for this interpreter"


@unittest.skipIf(MISSING, f"the kit's dependencies are not importable here: {MISSING}")
class RelayKitShapes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prv = ec.PrivateKey(bytes.fromhex("11" * 32))
        cls.pub = cls.prv.get_public_key()
        cls.spk = script.p2wpkh(cls.pub)
        cls.payload = bytes(range(256)) * 8            # 2,048 bytes, enough to need several pushes
        # Over Core's 400,000 WU, which is what makes a reveal non-standard there and is the whole point
        # of the test. A 2 KB file would pass every other check and quietly fail that one.
        cls.big_payload = bytes(range(256)) * 2_000    # 512,000 bytes
        cls.coin = {"txid": "ab" * 32, "vout": 0, "value": 150_000}

    def test_envelope_round_trip(self):
        sc = kit.envelope(self.pub.xonly(), self.payload, "video/mp4")
        ctype, body = kit.parse_envelope(sc)
        self.assertEqual(ctype, "video/mp4")
        self.assertEqual(body, self.payload)

    def test_envelope_without_a_content_type_is_plain_data(self):
        sc = kit.envelope(self.pub.xonly(), b"just bytes")
        ctype, body = kit.parse_envelope(sc)
        self.assertIsNone(ctype)
        self.assertEqual(body, b"just bytes")

    def test_a_short_coin_says_what_is_short(self):
        from embit.transaction import TransactionOutput
        out = TransactionOutput(140_000, self.spk)
        small = dict(self.coin, value=10_000)
        with self.assertRaises(SystemExit) as caught:
            kit.build(self.prv, self.pub, self.spk, small, [out], 1.0)
        self.assertIn("short", str(caught.exception))
        self.assertIn("10,000", str(caught.exception))

    def test_preflight_passes_end_to_end(self):
        tmp = Path(self.__class__.__name__ + ".mp4")
        tmp.write_bytes(self.big_payload)
        try:
            ok, rows, m = kit.preflight(self.prv, self.pub, self.spk, str(tmp), 0.1, 150_000)
        finally:
            tmp.unlink()
        self.assertTrue(ok, [label for label, good in rows if not good])
        self.assertEqual(m["payload"], len(self.big_payload))
        self.assertEqual(m["content_type"], "video/mp4")
        self.assertLessEqual(m["weight"], kit.MAX_STANDARD_TX_WEIGHT)
        self.assertGreater(m["weight"], 400_000)

    def test_preflight_names_the_money_check(self):
        tmp = Path(self.__class__.__name__ + "-2.mp4")
        tmp.write_bytes(self.big_payload)
        try:
            _, rows, _ = kit.preflight(self.prv, self.pub, self.spk, str(tmp), 0.1, 150_000)
        finally:
            tmp.unlink()
        labels = [label for label, _ in rows]
        self.assertTrue(any("MONEY COMES BACK" in label for label in labels), labels)
        self.assertGreaterEqual(len(rows), 10)

    def test_a_real_file_over_the_limit_is_refused_whole(self):
        too_big = b"\x00" * 4_000_000
        with self.assertRaises(SystemExit) as caught:
            kit.fit_witness(self.prv, self.pub, self.spk, self.coin, too_big, 0.1, "video/mp4")
        self.assertIn("carries whole", str(caught.exception))

    def test_the_script_path_message_is_the_one_bitcoin_core_computes(self):
        """The bug that would have failed the run, 2026-09-17.

        embit's sighash_taproot takes ext_flag separately and defaults it to 0, so passing `script=`
        without `ext_flag=1` writes a spend_type byte of 0 while still appending the tapscript
        extension. embit signs and verifies that happily; both of our DOG Mode nodes answered
        `mempool-script-verify-flag-failed (Invalid Schnorr signature)`. The kit signs its own BIP341
        message now, and this test pins it to embit's correct call and away from the broken one."""
        from embit.transaction import Transaction as Tx
        commit, reveal, leaf, n, fee, weight, vsize = kit.fit_witness(
            self.prv, self.pub, self.spk, self.coin, self.payload, 0.1, "video/mp4")
        parsed = Tx.parse(reveal.serialize())
        sc = parsed.vin[0].witness.items[1]
        tr_spk, _ = kit.taproot_from_leaf(self.pub, kit.leaf_hash(sc))
        value = commit.vout[0].value

        ours = kit.bip341_sighash(parsed, 0, [tr_spk], [value], leaf_script=sc)
        parsed.clear_cache()
        right = parsed.sighash_taproot(0, [tr_spk], [value], sighash=0, ext_flag=1,
                                       script=script.Script(sc), leaf_version=0xC0)
        parsed.clear_cache()
        wrong = parsed.sighash_taproot(0, [tr_spk], [value], sighash=0,
                                       script=script.Script(sc), leaf_version=0xC0)
        self.assertEqual(ours, right, "the kit's BIP341 message must equal embit's ext_flag=1 message")
        self.assertNotEqual(ours, wrong, "the kit must not be signing the spend_type 0 message again")
        self.assertTrue(ec.PublicKey.from_xonly(self.pub.xonly()).schnorr_verify(
            ec.SchnorrSig.parse(parsed.vin[0].witness.items[0]), ours))

    def test_the_key_path_message_matches_embit(self):
        from embit.transaction import Transaction as Tx
        commit, reveal, leaf, n, fee, weight, vsize = kit.fit_witness(
            self.prv, self.pub, self.spk, self.coin, self.payload, 0.1, "video/mp4")
        value = commit.vout[0].value
        rc, _, _, _ = kit.build_keypath_reclaim(self.prv, self.pub, self.spk, commit.txid().hex(), 0,
                                                value, leaf, 3.0)
        parsed = Tx.parse(rc.serialize())
        tr_spk, _ = kit.taproot_from_leaf(self.pub, leaf)
        ours = kit.bip341_sighash(parsed, 0, [tr_spk], [value])
        parsed.clear_cache()
        theirs = parsed.sighash_taproot(0, [tr_spk], [value], sighash=0)
        self.assertEqual(ours, theirs)

    def test_the_message_reverses_the_txid_the_way_the_serializer_does(self):
        """The kit's own implementation got this wrong first: embit keeps a txid in display order and
        reverses it on serialization, so a message built from the raw attribute hashes the wrong bytes
        and nothing offline notices."""
        from embit.transaction import Transaction as Tx
        commit, reveal, leaf, n, fee, weight, vsize = kit.fit_witness(
            self.prv, self.pub, self.spk, self.coin, self.payload, 0.1, "video/mp4")
        raw = reveal.serialize()
        parsed = Tx.parse(raw)
        # the attribute holds the txid the way an explorer prints it
        self.assertEqual(parsed.vin[0].txid.hex(), commit.txid().hex())
        # and the bytes on the wire are that, reversed: the message has to hash these
        self.assertIn(bytes(reversed(parsed.vin[0].txid)), raw[:64])
        self.assertNotIn(parsed.vin[0].txid, raw[:64])

    def test_sweep_signs_every_input_and_pays_one_address(self):
        coins = [{"txid": "ab" * 32, "vout": 0, "value": 30_000},
                 {"txid": "cd" * 32, "vout": 1, "value": 120_000}]
        dest = script.p2wpkh(ec.PrivateKey(bytes.fromhex("22" * 32)).get_public_key())
        tx, fee, weight, vsize = kit.build_sweep(self.prv, self.pub, coins, dest, 3.0)
        self.assertEqual(len(tx.vout), 1)
        self.assertEqual(tx.vout[0].script_pubkey.data, dest.data)
        self.assertEqual(tx.vout[0].value, 150_000 - fee)
        self.assertEqual(fee, -(-vsize * 3 // 1))
        parsed = Transaction.parse(tx.serialize())       # verify on the bytes, never on the signer
        pkh = script.p2pkh_from_p2wpkh(script.p2wpkh(self.pub))
        for i, c in enumerate(coins):
            parsed.clear_cache()
            h = parsed.sighash_segwit(i, pkh, c["value"], sighash=SIGHASH.ALL)
            sig, sec = parsed.vin[i].witness.items
            self.assertEqual(sec, self.pub.sec())
            self.assertTrue(ec.PublicKey.parse(sec).verify(ec.Signature.parse(sig[:-1]), h), f"input {i}")

    def test_sweep_refuses_to_leave_dust(self):
        coins = [{"txid": "ab" * 32, "vout": 0, "value": 600}]
        dest = script.p2wpkh(ec.PrivateKey(bytes.fromhex("22" * 32)).get_public_key())
        with self.assertRaises(SystemExit) as caught:
            kit.build_sweep(self.prv, self.pub, coins, dest, 3.0)
        self.assertIn("dust", str(caught.exception))


@unittest.skipIf(MISSING, f"the kit's dependencies are not importable here: {MISSING}")
class TheConfig(unittest.TestCase):
    def config(self, data):
        d = tempfile.mkdtemp()
        p = Path(d) / "nodes.json"
        p.write_text(json.dumps(data))
        return p

    def test_a_cli_call_carries_its_arguments_on_stdin(self):
        # `cat` stands in for bitcoin-cli: it answers with exactly what it was given on stdin
        node = kit.Node({"name": "echo", "cli": "cat # {method}"})
        self.assertEqual(node.rpc("sendrawtransaction", "ab" * 4), "ab" * 4)
        self.assertEqual(node.rpc("testmempoolaccept", ["aa", "bb"]), ["aa", "bb"])

    def test_a_method_is_a_name_and_nothing_else(self):
        node = kit.Node({"name": "echo", "cli": "cat # {method}"})
        with self.assertRaises(ValueError):
            node.rpc("getinfo; rm -rf ~")

    def test_a_node_is_reached_exactly_one_way(self):
        with self.assertRaises(SystemExit):
            kit.Node({"name": "both", "cli": "bitcoin-cli -stdin {method}", "umbrel": "umbrel@umbrel.local"})
        with self.assertRaises(SystemExit):
            kit.Node({"name": "no method", "cli": "bitcoin-cli -stdin"})

    def test_a_test_needs_a_node_to_send_and_one_to_watch(self):
        p = self.config({"nodes": [{"name": "alone", "cli": "bitcoin-cli -stdin {method}"}]})
        with self.assertRaises(SystemExit):
            kit.load_config(str(p))

    def test_relative_paths_are_read_against_the_config(self):
        p = self.config({"nodes": [{"name": "a", "cli": "x {method}"}, {"name": "b", "umbrel": "u@h"}],
                         "key_file": "key", "record_dir": "records"})
        cfg = kit.load_config(str(p))
        self.assertEqual(cfg["key_file"], (p.parent / "key").resolve())
        self.assertEqual(cfg["record_dir"], (p.parent / "records").resolve())
        self.assertEqual(cfg["control"], "mempool.space (Core policy)")

    def test_the_example_config_loads(self):
        cfg = kit.load_config(str(HERE / "nodes.example.json"))
        self.assertGreaterEqual(len(cfg["nodes"]), 2)


if __name__ == "__main__":
    unittest.main()
