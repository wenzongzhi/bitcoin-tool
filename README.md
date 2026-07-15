# Bitcoin tool for study
This is a open source bitcoin tool.
You can use this tool to complete the following task
- Calculate the hash value of any file and any string
- Generate a 32 bytes (256 bit) Bitcoin private key
- Generate compressed/uncompressed public keys and P2PKH addresses from a private key
- Generate P2PKH, P2WPKH, P2SH-P2WPKH, and P2TR addresses from a compressed public key
- Generate a P2PKH address from an uncompressed public key
- Create encrypted or plaintext BIP39/BIP84 wallets and derive P2WPKH addresses from an account xpub
- Sync issued wallet addresses through an Esplora API and cache balance, UTXOs, and transactions
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

- create an AES-encrypted wallet with optional 256-bit entropy
```bash
$ python bitcoin_tool.py createwallet --wallet-name "my_BTC_01" --password "test-password"
$ python bitcoin_tool.py createwallet --wallet-name "my_BTC_02" --entropy-hex "0000000000000000000000000000000000000000000000000000000000000000" --password "test-password"
```

Encrypted wallet creation does not print the mnemonic. Use the explicit command below when it must be viewed:
```bash
$ python bitcoin_tool.py getmnemonic --wallet-name "my_BTC_01" --password "test-password"
```

- create a plaintext wallet for experiments only
```bash
$ python bitcoin_tool.py createwallet --wallet-name "unsafe_test_wallet"
```

Plaintext wallets do not require `--password` when displaying the mnemonic:
```bash
$ python bitcoin_tool.py getmnemonic --wallet-name "unsafe_test_wallet"
```

- derive successive P2WPKH receiving addresses
```bash
$ python bitcoin_tool.py getnewaddress --wallet-name "my_BTC_01"
```

- derive a P2WPKH change address
```bash
$ python bitcoin_tool.py getnewaddress --wallet-name "my_BTC_01" --change
```

- export the BIP84 account xpub
```bash
$ python bitcoin_tool.py exportxpub --wallet-name "my_BTC_01" --password "test-password"
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

- start the interactive shell with completion
```bash
$ python bitcoin_tool.py shell
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

Use `--datadir PATH` on a wallet command, or set `BITCOIN_TOOL_DATADIR`, to override this location. Each issued address is recorded as public metadata in `issued_addresses`; private keys are never stored separately.

Wallets store the BIP84 account xpub (`m/84'/0'/0'`) so `getnewaddress` and `rebuildaddressbook` do not need to decrypt the mnemonic. The account xpub cannot spend coins, but it can reveal every receiving and change address in that account. Keep it private unless you intentionally need a watch-only setup.

`syncwallet` reads issued addresses from `wallets.json`, queries an Esplora-compatible backend, and writes public chain state into `wallet_cache.json` in the same data directory. `getbalance`, `listunspent`, and `listtransactions` read only this cache and do not perform network requests.

Only addresses already created by `getnewaddress` are synced. If you used addresses outside this tool's issued address book, create or rebuild the address records first.

The default sync backend is Blockstream's public Esplora API at `https://blockstream.info/api`. Querying a public backend reveals the wallet addresses you ask about to that backend. For better privacy, use `--backend-url` with a trusted or self-hosted Esplora server.

Existing `wallets.json` files in the project root are not moved automatically. Move the file to the user data directory, or use `--datadir` with the old directory explicitly.

Passwords passed on the command line may be recorded in shell history. These wallet commands are intended for study and experimentation, not production custody.
