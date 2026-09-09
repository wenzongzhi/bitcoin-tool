# Bitcoin tool for study
This is an open source Bitcoin tool for study.

> **Warning:** This is an educational hot-wallet implementation. Do not use it to custody significant funds. Complete Testnet4 testing before any mainnet use. Public Esplora queries reveal queried wallet addresses to the backend.
You can use this tool to complete the following task
- Calculate the hash value of any file and any string
- Generate a 32 bytes (256 bit) Bitcoin private key
- Convert between BIP39 entropy hex and mnemonic words
- Generate compressed/uncompressed public keys and P2PKH addresses from a private key
- Generate P2PKH, P2WPKH, P2SH-P2WPKH, and P2TR addresses from a compressed public key
- Generate a P2PKH address from an uncompressed public key
- Sign and verify messages with raw secp256k1 ECDSA signatures
- Sign and verify P2PKH messages in Bitcoin Core format and P2WPKH messages in BIP322 simple format
- Create encrypted or plaintext BIP39 wallets with BIP44, BIP49, BIP84, and BIP86 accounts
- Create isolated mainnet or Testnet4 wallets and addresses
- Sync issued wallet addresses through an Esplora API and cache balance, UTXOs, and transactions
- Query one transaction's confirmation state without synchronizing a wallet
- Create, fund, sign, decode, broadcast, and sweep P2PKH/P2WPKH transactions
- Start an interactive `bitcoin-tool shell` with command completion

## Operating environment
- Python version: 3.12.6, other versions should also work.
- Install dependencies
```bash
pip install -r requirements.txt
```

## User guide
- generate private key
```bash
$ python bitcoin_tool.py gen
```

- calculate hash value of ASCII string
```bash
$ python bitcoin_tool.py hash -s "Satoshi Nakamoto"
```

```bash
$ python bitcoin_tool.py hash -s "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
```

- calculate hash value of Hex string
```bash
$ python bitcoin_tool.py hash -x "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
```

- calculate hash value of file
```bash
$ python bitcoin_tool.py hash -f "E:\github\privatekey\bitcoin.pdf"
```

- generate public key/P2PKH/P2WPKH/P2SH-P2WPKH/P2TR address
```bash
$ python bitcoin_tool.py addr --private-key-hex "1415926535897932384626433832795028841971693993751058209749445923"
```

- generate addresses from a compressed or uncompressed public key
```bash
$ python bitcoin_tool.py addr --public-key-hex "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
```

- sign a message with raw ECDSA over secp256k1
```bash
$ python bitcoin_tool.py ecdsa-sign --private-key-hex "0000000000000000000000000000000000000000000000000000000000000001" --message "hello"
```

- verify a raw ECDSA message signature
```bash
$ python bitcoin_tool.py ecdsa-verify --public-key-hex "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" --message "hello" --sign "304402200f2fff8620d8ffe97040f8cf72ae476ef8ff4412373929c0324ce8428d3352e702201845ae4903027667005846f8f0be3e5ed2db5c3826ba83a6e542e080792f9a9d"
```

- sign a message for both the compressed-key P2PKH and P2WPKH addresses
```bash
$ python bitcoin_tool.py bitcoin-sign-message --private-key-hex "0000000000000000000000000000000000000000000000000000000000000001" --message "hello"
```

The command prints a Bitcoin Core compact Base64 signature for the `1...` address and a BIP322 simple Base64 signature for the `bc1q...` address. It also prints each protocol's internal DER ECDSA signature for inspection.

- verify a Bitcoin Core-compatible legacy P2PKH signature
```bash
$ python bitcoin_tool.py bitcoin-verify-message --legacy-addr "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH" --message "hello" --sign "Base64-signature"
```

- verify a BIP322 simple P2WPKH signature
```bash
$ python bitcoin_tool.py bitcoin-verify-message --p2wpkh-addr "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" --message "hello" --sign "smpBase64-signature"
```

- create an AES-encrypted wallet with optional 256-bit entropy
```bash
$ python bitcoin_tool.py createwallet --wallet-name "my_BTC_01" --password "test-password"
$ python bitcoin_tool.py createwallet --wallet-name "my_BTC_02" --entropy-hex "0000000000000000000000000000000000000000000000000000000000000000" --password "test-password"
```

- create a wallet by importing a BIP39 mnemonic
```bash
$ python bitcoin_tool.py createwallet --wallet-name "imported_BTC_01" --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art" --password "test-password"
```

- create a Testnet4 wallet
```bash
$ python bitcoin_tool.py --network testnet4 createwallet --wallet-name "testnet4_BTC_01" --password "test-password"
$ python bitcoin_tool.py --network testnet4 getnewaddress --wallet-name "testnet4_BTC_01" --address-type p2wpkh
```

`--network` is a global option and must appear before the command name. It defaults to `mainnet`. Testnet4 wallets use coin type `1`, `tpub` account keys, and test-network address prefixes (`m`/`n`, `2`, `tb1q`, and `tb1p`).

Encrypted wallet creation does not print the mnemonic. Use the explicit command below when it must be viewed:
```bash
$ python bitcoin_tool.py getmnemonic --wallet-name "my_BTC_01" --password "test-password"
```

- convert BIP39 entropy hex to mnemonic words
```bash
$ python bitcoin_tool.py convert --entropy-hex-to-mnemonic "00000000000000000000000000000000"
```

- convert BIP39 mnemonic words back to entropy hex
```bash
$ python bitcoin_tool.py convert --mnemonic-to-entropy-hex "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
```

- create a plaintext wallet for experiments only
```bash
$ python bitcoin_tool.py createwallet --wallet-name "unsafe_test_wallet"
```

Plaintext wallets do not require `--password` when displaying the mnemonic:
```bash
$ python bitcoin_tool.py getmnemonic --wallet-name "unsafe_test_wallet"
```

- derive the next receiving address (P2WPKH by default)
```bash
$ python bitcoin_tool.py getnewaddress --wallet-name "my_BTC_01"
```

- derive receiving addresses from a specific account
```bash
$ python bitcoin_tool.py getnewaddress --wallet-name "my_BTC_01" --address-type p2pkh
$ python bitcoin_tool.py getnewaddress --wallet-name "my_BTC_01" --address-type p2sh-p2wpkh
$ python bitcoin_tool.py getnewaddress --wallet-name "my_BTC_01" --address-type p2wpkh
$ python bitcoin_tool.py getnewaddress --wallet-name "my_BTC_01" --address-type p2tr
```

- sign with an issued wallet address path
```bash
$ python bitcoin_tool.py bitcoin-sign-message --wallet-name "my_BTC_01" --path "m/84'/0'/0'/0/0" --password "test-password" --message "hello"
```

The path must already exist in one account's `issued_addresses`. Wallet message signing currently accepts issued P2PKH and P2WPKH paths. Omit `--password` for a plaintext wallet.

Bitcoin address message signing and verification are currently mainnet-only. Testnet4 wallet keys remain available internally for future transaction signing, but `bitcoin-sign-message` and `bitcoin-verify-message` reject `--network testnet4`.

- derive a change address from a specific account
```bash
$ python bitcoin_tool.py getnewaddress --wallet-name "my_BTC_01" --address-type p2wpkh --change
```

- export an account xpub (P2WPKH by default)
```bash
$ python bitcoin_tool.py exportxpub --wallet-name "my_BTC_01" --password "test-password"
$ python bitcoin_tool.py exportxpub --wallet-name "my_BTC_01" --address-type p2pkh --password "test-password"
```

- derive a P2WPKH address from an external account xpub
```bash
$ python bitcoin_tool.py derivepub --xpub "xpub..." --branch 0 --index 0
```

- rebuild issued address records from the deterministic wallet state
```bash
$ python bitcoin_tool.py rebuildaddressbook --wallet-name "my_BTC_01"
```

- sync issued wallet addresses through the default Esplora backend
```bash
$ python bitcoin_tool.py syncwallet --wallet-name "my_BTC_01"
```

- sync a Testnet4 wallet
```bash
$ python bitcoin_tool.py --network testnet4 syncwallet --wallet-name "testnet4_BTC_01"
$ python bitcoin_tool.py --network testnet4 getbalance --wallet-name "testnet4_BTC_01"
$ python bitcoin_tool.py --network testnet4 listunspent --wallet-name "testnet4_BTC_01"
$ python bitcoin_tool.py --network testnet4 listtransactions --wallet-name "testnet4_BTC_01"
```

- query one transaction's current confirmation state without scanning wallet addresses
```bash
$ python bitcoin_tool.py --network testnet4 gettransactionstatus --txid "<64-character-txid>"
```

- sync through a self-hosted Esplora backend
```bash
$ python bitcoin_tool.py syncwallet --wallet-name "my_BTC_01" --backend-url "http://127.0.0.1:3002/api"
```

- read cached wallet balance
```bash
$ python bitcoin_tool.py getbalance --wallet-name "my_BTC_01"
```

- list cached spendable UTXOs
```bash
$ python bitcoin_tool.py listunspent --wallet-name "my_BTC_01"
$ python bitcoin_tool.py listunspent --wallet-name "my_BTC_01" --min-confirmations 1
```

- list cached wallet transactions
```bash
$ python bitcoin_tool.py listtransactions --wallet-name "my_BTC_01"
$ python bitcoin_tool.py listtransactions --wallet-name "my_BTC_01" --limit 50
```

## Raw transactions

The first transaction release supports confirmed P2PKH or native P2WPKH wallet inputs, `SIGHASH_ALL`, deterministic largest-first coin selection, BIP44/BIP84 change, exact decimal sat/vB fee rates, dust handling, and Esplora broadcasting. A transaction cannot mix P2PKH and P2WPKH inputs.

Start on Testnet4. Create an unsigned destination template:

```bash
$ python bitcoin_tool.py --network testnet4 createrawtransaction --output "tb1q...:25000"
```

Fund the template from the wallet's confirmed UTXO cache. By default this synchronizes the wallet first; `--cache-only` explicitly uses an existing cache:

```bash
$ python bitcoin_tool.py --network testnet4 fundrawtransaction --wallet-name "testnet4_BTC_01" --raw-tx-hex "<unsigned-hex>" --address-type p2wpkh --fee-rate-sat-vb 2 --max-fee-sats 5000
```

The command writes a versioned funded JSON document containing the unsigned transaction and its prevout metadata. Selected UTXOs are temporarily reserved, and an issued change index is never rolled back or reused.

Sign and locally verify the funded document. Encrypted wallets prompt for the password without echoing it:

```bash
$ python bitcoin_tool.py --network testnet4 signrawtransactionwithwallet --wallet-name "testnet4_BTC_01" --transaction-file "funded-<draft-id>.json" --max-fee-sats 5000
```

Decode either legacy or SegWit raw hex:

```bash
$ python bitcoin_tool.py --network testnet4 decoderawtransaction --raw-tx-hex "<signed-hex>"
```

Broadcast the signed document after local signature, amount, fee, network, txid, and serialization checks:

```bash
$ python bitcoin_tool.py --network testnet4 sendrawtransaction --transaction-file "funded-<draft-id>.signed.json"
```

`sendtoaddress` runs synchronization, funding, change issuance, signing, local verification, signed-document persistence, confirmation, and broadcast as one command:

```bash
$ python bitcoin_tool.py --network testnet4 sendtoaddress --wallet-name "testnet4_BTC_01" --to-address "tb1q..." --amount-sats 25000 --address-type p2wpkh --fee-rate-sat-vb 2 --max-fee-sats 5000
```

`sendall` spends every eligible confirmed UTXO of the selected wallet input type into one destination output. The destination amount is the total input value minus the fee, and no change address or change output is created:

```bash
$ python bitcoin_tool.py --network testnet4 sendall --wallet-name "testnet4_BTC_01" --to-address "tb1q..." --address-type p2wpkh --fee-rate-sat-vb 2 --max-fee-sats 5000
```

UTXOs below `--min-confirmations`, explicitly named by `--exclude-utxo`, reserved by another draft, or recorded as pending-spent are not eligible. P2PKH and P2WPKH inputs cannot be mixed, so choose the account to sweep with `--address-type`.

`--max-fee-sats` is a hard ceiling. `sendall` rejects the draft before signing when the estimated fee exceeds it, and performs the check again against the final signed transaction before any broadcast attempt.

Use `--confirmation-target 6` instead of `--fee-rate-sat-vb` to use the Esplora fee estimate. `fundrawtransaction` and `sendtoaddress` accept `--include-utxo txid:vout`; all three funding commands accept `--exclude-utxo txid:vout` for deterministic Testnet4 experiments.

Transient Esplora GET failures are retried twice by default with exponential backoff. Use `--retries N` to change this. Increasing `--timeout` does not fix a server that actively closes the connection. If the default Testnet4 service is unreachable from your network, select another trusted Testnet4 Esplora instance with `--backend-url`; the tool verifies its genesis block before reading wallet data or broadcasting.

Add `--dry-run` to `sendtoaddress` or `sendall` to synchronize, fund, sign, and save the result without broadcasting. `sendtoaddress` permanently issues any required change address; `sendall` never creates change.

The same transaction commands support mainnet when `--network` is omitted. Broadcasting on mainnet is blocked unless that invocation includes `--allow-mainnet`; an interactive `yes` confirmation is still required unless `--yes` is also supplied. Review the saved signed JSON with an independent decoder before broadcasting.

This release does not spend P2SH-P2WPKH or P2TR outputs and does not implement mixed input types, PSBT, RBF, fee bumping, or Taproot transaction signing.

All transaction amounts and UTXO values are integer satoshis. Fee rates are exact decimal sat/vB values and fees are rounded upward to satoshis. CLI txids use normal display byte order; outpoint hashes are reversed to little-endian only during raw transaction serialization.

Funded and signed files are versioned JSON documents (`bitcoin-tool-funded-transaction` and `bitcoin-tool-signed-transaction`, version `1`). A funded document records the selected outpoints, prevout values/scripts/addresses/paths/accounts, unsigned transaction hex, outputs, fee request, change position, wallet, network, and draft reservation ID. Signing treats every field as untrusted and checks it against the raw transaction, current wallet address book, UTXO cache, and draft reservation before deriving a private key. Unsupported document versions fail explicitly; there is no silent format conversion.

- start the interactive shell with completion
```bash
$ python bitcoin_tool.py shell
$ python bitcoin_tool.py --network testnet4 shell
```

Inside the shell, use the command name without `python bitcoin_tool.py`:
```text
bitcoin-tool> hash -s "Satoshi Nakamoto"
bitcoin-tool> getnewaddress --wallet-name "my_BTC_01"
bitcoin-tool> help addr
bitcoin-tool> exit
```

When `prompt_toolkit` is installed from `requirements.txt`, the shell supports command/option completion and colored input. Commands are cyan, options are green, quoted strings are blue, numbers are yellow, long hexadecimal values are magenta, and unknown commands are red. If `prompt_toolkit` is unavailable, the tool falls back to the basic `cmd` shell with command and option completion but without input coloring.

Wallet data is stored outside the source tree by default:

- Windows: `%LOCALAPPDATA%\bitcoin-tool\wallets.json`
- Linux: `~/.local/share/bitcoin-tool/wallets.json`
- macOS: `~/Library/Application Support/bitcoin-tool/wallets.json`

Testnet4 uses separate files in the same directory:

- `wallets_testnet4.json`
- `wallet_cache_testnet4.json`

Mainnet continues to use `wallets.json` and `wallet_cache.json`; no mainnet file migration or schema rewrite is performed.

Use `--datadir PATH` on a wallet command, or set `BITCOIN_TOOL_DATADIR`, to override this location. Private keys are never stored separately.

Wallet format version 3 stores four independent account objects under `accounts`:

- `bip44-account-0`: P2PKH, `m/44'/0'/0'`
- `bip49-account-0`: P2SH-P2WPKH, `m/49'/0'/0'`
- `bip84-account-0`: P2WPKH, `m/84'/0'/0'`
- `bip86-account-0`: P2TR, `m/86'/0'/0'`

Testnet4 uses the same account structure with paths `m/44'/1'/0'`, `m/49'/1'/0'`, `m/84'/1'/0'`, and `m/86'/1'/0'`.

Each account owns its account xpub, receiving/change indexes, and `issued_addresses`. The account xpub cannot spend coins, but it reveals every receiving and change address in that account. Keep it private unless you intentionally need a watch-only setup.

Wallet format versions 1 and 2 are rejected. There is no automatic migration: recreate the wallet from its mnemonic to obtain the version 3 structure. Wallet cache version 1 is also rejected; remove the old `wallet_cache.json` and run `syncwallet` to create a fresh cache.

`syncwallet` reads issued addresses from every account in `wallets.json`, queries an Esplora-compatible backend, and writes public chain state into `wallet_cache.json` in the same data directory. Cached addresses and UTXOs retain their `account_id` and `address_type`. `getbalance`, `listunspent`, and `listtransactions` read only this cache and do not perform network requests.

Only addresses already created by `getnewaddress` are synced. If you used addresses outside this tool's issued address book, create or rebuild the address records first.

The mainnet default sync backend is Blockstream's public Esplora API at `https://blockstream.info/api`. The Testnet4 default is `https://mempool.space/testnet4/api`. Before querying wallet addresses, `syncwallet` verifies the backend's genesis block against the selected network. Querying a public backend reveals the wallet addresses you ask about to that backend. For better privacy, use `--backend-url` with a trusted or self-hosted Esplora server.

Existing `wallets.json` files in the project root are not moved automatically. Move the file to the user data directory, or use `--datadir` with the old directory explicitly.

Passwords and private keys passed on the command line may be recorded in shell history or visible in process listings. These wallet commands are intended for study and experimentation, not production custody.

`ecdsa-sign` signs `sha256(message_utf8)` with deterministic ECDSA/RFC6979 and outputs canonical DER signature hex. This is a raw cryptographic signature helper, not Bitcoin Core's legacy `signmessage` envelope format.

`bitcoin-sign-message` produces two separate address-proof formats. Legacy P2PKH uses the compact recoverable Base64 format accepted by Bitcoin Core `verifymessage`. Native SegWit P2WPKH uses BIP322 simple and includes the current `smp` prefix; `bitcoin-verify-message` also accepts the older unprefixed BIP322 encoding for compatibility. The displayed DER value is only the ECDSA component inside its protocol and is not, by itself, a complete address-verifiable message signature.

A P2PKH address and a P2WPKH address are not converted into one another. This tool derives both locking scripts from the same compressed public key, so one private key controls both resulting addresses. Third-party and hardware-wallet support varies; use the Base64 value for the matching protocol and address type.
