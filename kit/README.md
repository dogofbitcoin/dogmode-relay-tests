# The relay test kit

The tool that ran the [4 meg test](../4meg/): it sends what Bitcoin Core refuses through one DOG Mode node, reads
it arriving in your other DOG Mode nodes, and checks that a Core-policy node never sees it. One Python file.

**It spends real bitcoin**, a little: fund its throwaway key with only what a test needs, and sweep it home after.
Every command that could spend is a dry run until you add `--go`, and `preflight` proves the whole big test offline,
the money's way back included, before you fund anything. Read `relaytest.py` before you run it.

## Set up

```
python3 -m venv ~/.venvs/dogmode && ~/.venvs/dogmode/bin/pip install -r requirements.txt
mkdir -p ~/.dogmode-relaytest && cp nodes.example.json ~/.dogmode-relaytest/nodes.json
```

Then name your nodes in `~/.dogmode-relaytest/nodes.json` (or point `--config` or `DOGMODE_RELAYTEST_CONFIG` at
another file). The first node sends; every node is asked `testmempoolaccept` first and watched after. A node is
reached one of two ways:

| | |
|---|---|
| `"cli": "... bitcoin-cli -stdin {method}"` | any shell command ending in `bitcoin-cli -stdin {method}`: local, over `ssh`, through `docker exec -i`. The call's arguments go on its stdin, never on the command line, because a 3.9 MB transaction is 7.7 MB of hex and one command line argument dies at 128 KB |
| `"umbrel": "umbrel@umbrel.local"` | the Dog of Bitcoin DOG Mode package on umbrelOS, over `ssh`. A small program runs on the Umbrel, reads the app's RPC password there and asks the app's node, so the password never leaves the box |

`api` is the Core-policy control, an esplora API (mempool.space by default, or your own). A relative path in the
config is read against the config file's folder.

## Run it

```
python3 relaytest.py key                                    # make the throwaway key, print its address
python3 relaytest.py status                                 # every node, the key's coins, what each test costs
python3 relaytest.py preflight --inscribe FILE --feerate 0.1   # offline, before funding: 12 checks
python3 relaytest.py dust                                   # the 1 sat test, dry run; --go sends it
python3 relaytest.py big --inscribe FILE --feerate 0.1      # the big test, dry run; --go sends it
python3 relaytest.py watch TXID                             # every node, and the control
python3 relaytest.py decode TXID --expect FILE              # the file back out of each node's mempool
python3 relaytest.py reclaim --go                           # the big test's coin back, by key path, through Core
python3 relaytest.py sweep bc1q... --go                     # everything at the key home to your wallet
```

**0.1 sat/vB is the floor**, Core's own default since v30 and DOG Mode's too, so run the big test there: the fee a
miner could take is then about 96,000 sats, and taking it would cost that miner a block's worth of better paying
transactions. `reclaim` spends the coin back through a Core-policy node right after, and once that confirms the big
transaction can never be mined. Our two runs cost 1,268 sats in fees, start to finish.

The scars, each paid for on mainnet, are at the top of `relaytest.py`. The one that matters most: the kit writes
the BIP341 signature message itself and refuses to sign when embit's disagrees, because a library that verifies its
own signature proves nothing, and every node refused ours until it did.

## Tests

```
~/.venvs/dogmode/bin/python -m unittest discover -s . -p "test_*.py"
```

Offline: they build and verify every shape against a key they make themselves, and never touch a node or the
network.

If you want a relay behavior tested on mainnet across real dog nodes and would rather not run this yourself, ask
on [the DOG Mode discussions](https://github.com/bitcoindogmode/bitcoin/discussions/9).
