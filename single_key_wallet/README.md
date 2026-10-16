# Single-Key Wallet v1

One raw secp256k1 private key controls five deterministic address representations.
This platform is independent of the HD wallet. It has no mnemonic, xpub, path,
account, branch, address index, or gap discovery. Repeated receive requests return
the same address for the selected representation.

| Address identifier | Sync | Receive | Spend |
| --- | --- | --- | --- |
| `p2pkh-compressed` | yes | yes | yes |
| `p2pkh-uncompressed` | yes | yes | yes |
| `p2wpkh` | yes | yes | yes |
| `p2sh-p2wpkh` | yes | no | no |
| `p2tr` | yes | no | no |

The last two are derived and monitored for historical funds. Spending them is
not yet supported. Spending source support is independent of destination support:
standard P2PKH, P2SH, P2WPKH, P2WSH, and P2TR destinations are accepted.

## Storage

The existing application data directory and `BITCOIN_TOOL_DATADIR` convention
apply. `--datadir PATH` takes precedence. Files are separate from HD wallets:

| Network | Wallet file | Public cache |
| --- | --- | --- |
| mainnet | `single_key_wallets.json` | `single_key_wallet_cache.json` |
| testnet4 | `single_key_wallets_testnet4.json` | `single_key_wallet_cache_testnet4.json` |

Wallet records start at version 1 and contain `wallet_id`, `network`,
`key_origin`, `preferences`, `public_keys`, `addresses`, and one `secret`.
The secret is exactly a raw 32-byte scalar, never WIF. With a password it uses
AES-256-GCM and PBKDF2-HMAC-SHA256 (200,000 iterations, a new 16-byte salt and
12-byte nonce). Associated data binds the secret to the wallet name and public
metadata. Password changes generate a fresh salt and nonce. An omitted password
stores plaintext and the CLI warns accordingly; an explicitly empty password
still selects encryption.

The public cache retains complete transaction summaries, per-address stats,
UTXOs, reservations, and broadcast state. It never stores a private key or an HD
derivation field. Atomic replacement and file locks protect mutations.

## CLI

`--network` is a global option and appears before the command. It defaults to
mainnet. In a Testnet4 shell, omit the executable and the network option.

```powershell
python bitcoin_tool.py --network testnet4 singlekey-createwallet --wallet-name single01 --password "test-password"
python bitcoin_tool.py --network testnet4 singlekey-importkey --wallet-name imported01 --private-key-hex "<64-hex-private-key>" --password "test-password"
python bitcoin_tool.py --network testnet4 singlekey-importkey --wallet-name oldwallet --wif "<test-network-WIF>" --password "test-password"
python bitcoin_tool.py --network testnet4 singlekey-listwallets
python bitcoin_tool.py --network testnet4 singlekey-getaddresses --wallet-name single01
python bitcoin_tool.py --network testnet4 singlekey-getaddress --wallet-name single01
python bitcoin_tool.py --network testnet4 singlekey-getaddress --wallet-name single01 --address-type p2pkh-uncompressed
python bitcoin_tool.py --network testnet4 singlekey-syncwallet --wallet-name single01
python bitcoin_tool.py --network testnet4 singlekey-getbalance --wallet-name single01
python bitcoin_tool.py --network testnet4 singlekey-listunspent --wallet-name single01
python bitcoin_tool.py --network testnet4 singlekey-listtransactions --wallet-name single01
```

Generated keys, HEX imports and compressed WIF imports default to P2WPKH.
Uncompressed WIF imports preserve the marker in `key_origin`, default to
`p2pkh-uncompressed`, and immediately show the historical legacy address.
All imports still derive all five representations. WIF checksum, scalar, payload
length, network version and compression marker are validated.

Create/import do not print private keys. CLI secrets can appear in shell history
and process listings. Encrypted send/change/delete operations prompt without
echoing when `--password` is omitted.

## Balances And History

Sync verifies the backend genesis block, queries stats and UTXOs for all five
addresses, and uses complete Esplora history including pagination. It deduplicates
transactions shared by tracked addresses. An interrupted history fetch or a chain
tip change leaves the previous cache intact.

`detected_balance_sats` includes all five representations.
`spendable_balance_sats` includes only representations supported for spending;
it is a balance by capability, not a promise that every satoshi is currently
eligible for coin selection. `available_confirmed_sats` excludes locally reserved
or pending-spent inputs. Per-type confirmed balances use chain funded minus spent;
unconfirmed balances are the mempool delta and can be negative. Read commands use
only the cache; synchronize first for current chain state.

## Send And Preview

Exactly one of `--amount-sats` or `--all` is required. `--from-address-type` and
an explicit decimal `--fee-rate-sat-vb` are required. Only confirmed inputs of that
one representation are selected (default minimum: one confirmation).

```powershell
python bitcoin_tool.py --network testnet4 singlekey-send --wallet-name single01 --from-address-type p2wpkh --to "tb1q..." --amount-sats 50000 --fee-rate-sat-vb 2.5 --max-fee-sats 5000 --dry-run
python bitcoin_tool.py --network testnet4 singlekey-send --wallet-name oldwallet --from-address-type p2pkh-uncompressed --to "tb1q..." --all --fee-rate-sat-vb 2.5 --max-fee-sats 5000 --dry-run
```

Ordinary sends select deterministically largest-first. Change returns to the same
fixed source address, even when the wallet's default receive preference differs.
Dust change is absorbed into the fee. `--all` selects every eligible UTXO only
from the specified representation, creates one output, and subtracts the fee.
Nonpositive or dust destination amounts are rejected.

P2PKH-uncompressed estimates include the 65-byte public key. Fees are rounded
up and use a conservative signed-size estimate; the effective signed rate may
be slightly above the requested rate. The final serialized size and fee are
checked again after signing. Estimated and final maximum-fee rejection messages:

```text
error: estimated fee 1250 sats exceeds max fee 1000 sats
error: final fee 1012 sats exceeds max fee 1000 sats; transaction was not broadcast
```

Every signing operation unlocks the fixed key once, signs with deterministic
low-S ECDSA, and locally verifies each input. Online prepare and broadcast also
check each previous transaction's txid, output script and actual value. This is
especially necessary for legacy signatures, which do not commit to input amounts.
`--cache-only` skips prepare-time backend access and uses a recent public cache;
the actual broadcast still performs online prevout checks.

## Saved Transactions And Reservations

A dry run saves a `singlekey-signed-<operation-id>.json` file and reserves its
inputs. Review it, then broadcast the same file without regenerating a draft:

```powershell
python bitcoin_tool.py --network testnet4 singlekey-broadcast --wallet-name single01 --transaction-file "singlekey-signed-<operation-id>.json"
```

To abandon a draft before any broadcast attempt:

```powershell
python bitcoin_tool.py --network testnet4 singlekey-canceldraft --wallet-name single01 --operation-id "<operation-id>"
```

Reservation checks and writes are atomic across concurrent send calls, including
duplicate key imports sharing the same cache. Signing failures release the draft.
Reservations persist until cancellation or broadcast reconciliation; there is no
address reservation or change index.

Broadcast requires an interactive `yes` unless `--yes` is supplied. Mainnet also
requires `--allow-mainnet`. The destination, source representation, input total,
amount, change, fee and input count are shown before confirmation.

Before POST, the signed transaction and pending-spent outpoints are persisted.
If the connection closes, the outcome is `broadcast_unknown`; inputs remain
blocked because the node may already have accepted the transaction. Synchronize
to reconcile history. An explicit `singlekey-broadcast` can retry the identical
signed transaction while the outcome remains unknown; no automatic POST retry
or replacement transaction is generated.

## Lifecycle And Platform API

```powershell
python bitcoin_tool.py --network testnet4 singlekey-changepassword --wallet-name single01 --new-password "new-password"
python bitcoin_tool.py --network testnet4 singlekey-removewallet --wallet-name single01
```

Password removal is explicit via `--remove-encryption`. Deletion authenticates
encrypted wallets and refuses wallets with reserved or pending inputs.

```python
from pathlib import Path
from single_key_wallet import SingleKeyWalletService

service = SingleKeyWalletService(
    Path("single_key_wallets_testnet4.json"),
    Path("single_key_wallet_cache_testnet4.json"),
    network="testnet4",
)
service.create_wallet("single01", password="test-password")
service.sync_wallet("single01")
balance = service.get_balance("single01")
signed = service.prepare_send(
    "single01", "p2wpkh", "tb1q...", "2.5",
    amount_sats=50000, password="test-password", max_fee_sats=5000,
)
# Review signed, then explicitly request broadcast.
receipt = service.broadcast(signed)
```

`send()` combines these steps and defaults to a signed preview.
Use `broadcast=True` explicitly to broadcast, plus `allow_mainnet=True` for mainnet.
Public service methods return JSON-compatible data with no secret material.

## Tests

```powershell
python -m unittest discover -s single_key_wallet/tests -t . -v
python -m unittest discover -s tests -v
```

Tests use deterministic keys, known address/WIF vectors, the official BIP143
digest, temporary files, and fake Esplora backends. They perform no real broadcasts.
