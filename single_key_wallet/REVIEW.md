# Integration Review

Scope: existing wallet, transaction and CLI implementation, reviewed against
`SINGLE_KEY_WALLET_CODEX_SPEC_V2.md`. Only `bitcoin_tool.py` is changed among
existing production files. Existing HD services and tests remain intact.

## Existing Issues And Constraints

1. **P1: Legacy fee checks trust cached prevout values.**
   `tx/workflow.py:_validate_prevouts_against_wallet_and_cache` checks the document
   against local cached metadata, and `broadcast_signed_transaction` computes fees
   from that metadata without verifying raw funding transactions. An incorrect
   legacy prevout value can pass signature verification while understating the
   actual fee: legacy SIGHASH_ALL does not commit to input value. The independent
   single-key workflow verifies raw parent txids, output scripts, and values
   online before signing and again before broadcasting. The existing HD workflow
   is frozen by the specification; this finding is not patched there.

2. **P1: An uncertain HD broadcast is not durably marked before POST.**
   `tx/workflow.py:broadcast_signed_transaction` persists pending-spent state only
   after the backend returns a matching txid. A disconnect after remote acceptance
   leaves no durable record of that uncertain attempt; cancellation can release
   the signed draft's reservation. The new subsystem persists broadcast intent,
   signed bytes, and pending-spent inputs before POST. It retains them on failure,
   reconciles complete history, and permits only an explicit retry of identical
   bytes. Existing HD behavior is preserved as requested.

3. **P2: The existing transaction primitives are not a neutral package API.**
   `tx/__init__.py` imports HD workflows, `tx/model.py:Prevout` requires a
   derivation path, and `tx/verifier.py:verify_transaction_input` accepts only
   compressed P2PKH public keys. Direct reuse would violate isolation and prevent
   historical uncompressed-key spending. New models, codec, sighash and verifier
   live under `single_key_wallet/`, use no fake HD metadata, and use coincurve for
   ECDSA rather than implementing elliptic-curve arithmetic.

4. **P2: The fallback cmd shell splits hyphenated command tokens.**
   `cmd.Cmd` does not include a hyphen in its default command identifier set.
   New singlekey-prefixed commands need targeted parsing in `BitcoinToolShell`.
   Command/option completion is generated from argparse as before; the targeted
   parser leaves the existing command dispatch unchanged.

## Protocol References

SegWit signature digests and compressed-key requirements follow
[BIP143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki).
The official native-P2WPKH digest vector is included in the new tests.

Taproot internal/output-key metadata uses the repository's existing BIP341
key-tweak helper and Bech32m address generation; this version does not sign
Taproot inputs. See
[BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki).

WIF import validates the network version, Base58Check checksum, scalar range
and optional trailing `0x01`, matching
[Bitcoin Core key encoding](https://github.com/bitcoin/bitcoin/blob/master/src/key_io.cpp).

## New Boundary Checks

- Raw secret is stored once; encrypted records authenticate public metadata.
- Mainnet/testnet4 files and backend genesis checks are independent.
- All five address representations are tracked, while receive/spend capabilities
  are explicit and only three input types can be used.
- Same-type source filtering, dust handling, distinct input size estimates,
  final rate checks, and estimated/final maximum-fee rejection protect payments.
- Signed documents are checked against raw serialization, local signatures,
  wallet public metadata, reservations and actual parent outputs before POST.
- Complete sync merges current reservations under lock and does not overwrite
  the cache with a partially fetched history.
- Broadcast state is public-only and retains enough data to recover after a
  restart or uncertain network response.

Live node acceptance is not part of these local tests. The three spending paths
are covered on both network parameter sets with fake backends. Real Testnet4
node validation remains a separate integration step.
