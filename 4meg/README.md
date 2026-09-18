# The 4 meg test

On 2026-09-17 at 23:14:20 UTC one Bitcoin transaction of 3,847,522 weight units, 96 percent of a whole block and 9.6
times what Bitcoin Core will relay, carried the 10 second video in this folder from one DOG Mode node to another in
4 seconds. Bitcoin Core nodes refused it. Its coin was then spent back to the test key, so it was never mined and its
96,189 sat fee was never paid. The 1 sat test of 2026-09-14 is checked here too.

## Check it

```
git clone https://github.com/dogofbitcoin/dogmode-relay-tests
cd dogmode-relay-tests/4meg
python3 verify.py dog.mp4
```

Python 3.8 or newer, standard library only. Read `verify.py` before you run it: it is under 200 lines, it reads two
confirmed transactions from mempool.space (or any esplora API with `--api`, your own included) and nothing else, and
it holds no key.

What it checks, and why each one holds:

1. **`dog.mp4` is the file that was sent**, by its sha256.
2. **Block 967,483 committed to exactly this video.** The commit's output is a taproot key, and a taproot key is the
   test key tweaked by the hash of a script. That script is an ordinals envelope holding the whole video, rebuilt
   here from the video alone. Change one byte and it is a different key.
3. **The 3.85 MB transaction's id.** A transaction id never covers the witness, so the id of a transaction nobody will
   ever mine rebuilds from public data: the commit it spent and the 1,000 sats it paid back.
4. **Its weight**, from the sizes of its parts: over Core's 400,000, under DOG Mode's 3,900,000.
5. **The 1 sat transaction's id**, from the coin it spent and its two outputs.

What it prints:

```
PASS  the video is the file that was sent
      3,824,965 bytes, sha256
      b3c9e3d8cb88dad1407dd43da8c5b30f114f42112eec1753589ff376b39ec937
PASS  block 967,483 committed to exactly this video
      on chain  eaed34c33798c2dba0870e6815dd25c1a2bd2105af7ce0672ad297037442a5b7
      rebuilt   eaed34c33798c2dba0870e6815dd25c1a2bd2105af7ce0672ad297037442a5b7
PASS  the 3.85 MB transaction's id
      rebuilt 5d072e6797b1ecec273f5e9b0eb60aa5fc231f70fee86d3a0d52e4184ee3c29a
PASS  it weighs 3,847,522 WU, 9.6 times what Bitcoin Core relays
      Core relays up to 400,000, DOG Mode up to 3,900,000, a block holds 4,000,000
      961,881 vB at 0.100 sat/vB, 96,189 sats of fee offered, never paid:
      the coin was spent back first
PASS  the 1 sat transaction's id
      rebuilt 7a2aacd3ca2bf1b180c55d5c40254d627632ba91e2f3d956b061a6acc34b3e8a

Everything matches.
```

## The transactions

| | txid | mempool.space |
|---|---|---|
| the 1 sat test, never mined | `7a2aacd3ca2bf1b180c55d5c40254d627632ba91e2f3d956b061a6acc34b3e8a` | 404 |
| the commit, block 967,483 | `b7edb847dfa0a150f70874096d8ea70c6b13958f777ea8e84d77063d7f09c0d4` | 200 |
| the 3.85 MB reveal, never mined | `5d072e6797b1ecec273f5e9b0eb60aa5fc231f70fee86d3a0d52e4184ee3c29a` | 404 |
| the reclaim, block 967,483 | `075056975d1ea361af868966b7b7d5ae01d6c54909ad13d6c8e4fac187e9d7da` | 200 |
| the sweep home, block 967,529 | `1225ab154c39c01bea4b1242395ef9153eed0f57cd1cba74c3c4df2152310857` | 200 |

Every fee paid, start to finish, the two payments that funded the test key included: 1,268 sats. Offered and never
paid: 96,189 and 141.
