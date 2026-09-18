# DOG Mode relay tests

Mainnet tests of how [DOG Mode](https://github.com/bitcoindogmode/bitcoin) nodes relay what Bitcoin Core nodes refuse,
run by the Dog of Bitcoin Foundation, with everything you need to check them yourself. Nothing here holds a key or
sends a transaction: it reads the chain and checks.

| test | run | what it showed | check it |
|---|---|---|---|
| [4meg](4meg/) | 2026-09-14 and 2026-09-17 | a 3,847,522 weight unit transaction carrying a 10 second video crossed two DOG Mode nodes in 4 seconds while Bitcoin Core refused it; before it, a 1 sat output did the same | `cd 4meg && python3 verify.py dog.mp4` |

**[The kit](kit/)** is the tool that ran them: it sends what Bitcoin Core refuses through one DOG Mode node you name,
reads it arriving in the others, and checks that a Core-policy node never sees it. It spends a little real bitcoin,
so it proves everything offline first and dry runs until you add `--go`.

The write up, with the video: https://seed.dogofbitcoin.org/4meg. The readings, where the DOG Mode maintainers read
them: https://github.com/bitcoindogmode/bitcoin/pull/3#issuecomment-5722763923

If a check does not match, or you want a relay behavior tested on mainnet across real dog nodes, open an issue.

## License

The code and the text are MIT licensed ([LICENSE](LICENSE)). `4meg/dog.mp4` carries the Dog of Bitcoin character and
is not covered by that license; it is here so the test can be checked.
