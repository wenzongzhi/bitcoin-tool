"""
Copyright 2026 温中志 (Wen Zhongzhi)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import argparse
import cmd
import getpass
import json
import re
import shlex
import sys
from decimal import Decimal
from functools import lru_cache
from pathlib import Path
from btc.chainparams import (
    NETWORK_MAINNET,
    SUPPORTED_NETWORKS,
)
from btc.hash import sha256, dbl_sha256, sha256_file, dbl_sha256_file, show
from btc.private_key_gen import generate_32bytes_private_key, is_valid_privkey
from btc.btc_address_gen import (
    is_valid_public_key,
    privkey_to_pubkey,
    public_key_to_compressed,
    pubkey_to_p2pkh,
    p2tr_address,
    p2wpkh_bech32_address,
    p2sh_p2wpkh_address,
)
from version import __version__
from network import EsploraBackend, EsploraError
from sign import (
    MessageSignatureError,
    bitcoin_sign_message,
    ecdsa_sign_message,
    ecdsa_verify_message,
    verify_legacy_message,
    verify_p2wpkh_message,
)
from wallet import (
    DEFAULT_ADDRESS_TYPE,
    SUPPORTED_ADDRESS_TYPES,
    WalletError,
    create_wallet,
    default_wallet_cache_file,
    default_wallet_file,
    derive_p2wpkh_from_account_xpub,
    export_account_xpub,
    entropy_hex_from_mnemonic,
    get_cached_balance,
    get_mnemonic,
    get_new_address,
    get_wallet_signing_key,
    list_cached_transactions,
    list_cached_unspent,
    mnemonic_from_entropy_hex,
    rebuild_address_book,
    sync_wallet,
    wallet_requires_password,
)
from tx import (
    TransactionError,
    broadcast_signed_transaction,
    create_raw_transaction,
    decode_transaction,
    deserialize_transaction_hex,
    fund_all_transaction,
    fund_transaction,
    load_json_document,
    save_json_document,
    serialize_transaction_hex,
    sign_funded_transaction,
    transaction_metrics,
    validate_signed_document,
)
from tx.builder import parse_outpoint, parse_output_spec

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import Completer, Completion
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.lexers import Lexer
    from prompt_toolkit.styles import Style
except ImportError:
    PromptSession = None
    Completer = object
    Completion = None
    HTML = None
    Lexer = object
    Style = None


def cmd_hash(args):
    parser = args.parser
    
    if args.string is not None:
        data = args.string.encode("utf-8")
        print("input:", repr(args.string))
        print()
        show("SHA256", sha256(data))
        show("Double-SHA256", dbl_sha256(data))
        return
    elif args.hex is not None:
        try: 
            data = bytes.fromhex(args.hex)
        except ValueError:
            parser.error(f'invalid hex string: "{args.hex}"')
        print("input:", repr(args.hex))
        print()
        show("SHA256", sha256(data))
        show("Double-SHA256", dbl_sha256(data))
        return
    else:
        file_path = Path(args.file).expanduser().resolve()
        if not file_path.exists():
            #raise FileNotFoundError(f"File not found: {file_path}")
            parser.error(f'file not found: "{file_path}"')
        if not file_path.is_file():
            #raise ValueError(f"Not a file: {file_path}")
            parser.error(f'not a file: "{file_path}"')
            
        file_path = file_path.resolve()
        h1 = sha256_file(file_path)
        h2 = dbl_sha256_file(file_path)
        print("file:", file_path)
        print("SHA256(file)      =", h1.hex())
        print("Double-SHA256(file)=", h2.hex())

def cmd_gen(args):
    key_bytes, key_hex = generate_32bytes_private_key()
    print()

    print("32 Bytes original private number:   ", key_bytes)
    print(f"32 Bytes Hex private key:   ", key_hex)
    
def cmd_addr(args):
    if args.private_key_hex is not None:
        try:
            priv = bytes.fromhex(args.private_key_hex)
        except ValueError:
            args.parser.error("invalid hex private key")

        if not is_valid_privkey(priv):
            args.parser.error("invalid private key: must be 32 bytes and 1 <= key < secp256k1_n")

        pub_c = privkey_to_pubkey(priv, compressed=True)
        pub_u = privkey_to_pubkey(priv, compressed=False)
        print("compressed pubkey  :", pub_c.hex())
        print("uncompressed pubkey:", pub_u.hex())
        print()
        print("network                     :", args.network)
        print("P2PKH (compressed pubkey)  :", pubkey_to_p2pkh(pub_c, args.network))
        print("P2PKH (uncompressed pubkey):", pubkey_to_p2pkh(pub_u, args.network))
        print("P2WPKH                     :", p2wpkh_bech32_address(pub_c, args.network))
        print("P2SH-P2WPKH                :", p2sh_p2wpkh_address(pub_c, args.network))
        print("P2TR                        :", p2tr_address(pub_c, args.network))
        return

    try:
        pubkey = bytes.fromhex(args.public_key_hex)
    except ValueError:
        args.parser.error("invalid hex public key")

    if not is_valid_public_key(pubkey):
        args.parser.error(
            "invalid public key: expected a compressed (33-byte) or "
            "uncompressed (65-byte) secp256k1 public key"
        )

    compressed = len(pubkey) == 33
    pub_c = public_key_to_compressed(pubkey)
    print("input public key type        :", "compressed" if compressed else "uncompressed")
    if not compressed:
        print("P2PKH (uncompressed pubkey)  :", pubkey_to_p2pkh(pubkey, args.network))
    print("network                      :", args.network)
    print("compressed pubkey            :", pub_c.hex())
    print("P2PKH (compressed pubkey)    :", pubkey_to_p2pkh(pub_c, args.network))
    print("P2WPKH                       :", p2wpkh_bech32_address(pub_c, args.network))
    print("P2SH-P2WPKH                  :", p2sh_p2wpkh_address(pub_c, args.network))
    print("P2TR                          :", p2tr_address(pub_c, args.network))


def cmd_ecdsa_sign(args):
    try:
        result = ecdsa_sign_message(args.private_key_hex, args.message)
    except MessageSignatureError as exc:
        args.parser.error(str(exc))

    print("message                  :", result["message"])
    print("message hash (sha256)    :", result["message_hash"])
    print("signature format         :", result["signature_format"])
    print("signature hex            :", result["signature"])
    print("compressed public key    :", result["public_key_compressed"])
    print("uncompressed public key  :", result["public_key_uncompressed"])


def cmd_ecdsa_verify(args):
    try:
        valid = ecdsa_verify_message(args.public_key_hex, args.message, args.sign)
    except MessageSignatureError as exc:
        args.parser.error(str(exc))

    print("verification:", "success" if valid else "failed")


def cmd_bitcoin_sign_message(args):
    if args.network != NETWORK_MAINNET:
        args.parser.error("bitcoin message signing currently supports mainnet only")
    if args.private_key_hex is not None:
        if args.path is not None or args.password is not None or args.datadir is not None:
            args.parser.error(
                "--path, --password, and --datadir apply only to --wallet-name"
            )
        private_key_hex = args.private_key_hex
        source = "private key argument"
        wallet_key = None
        print(
            "WARNING: --private-key-hex may be visible in shell history and process listings.",
            file=sys.stderr,
        )
    else:
        if args.path is None:
            args.parser.error("--path is required with --wallet-name")
        try:
            wallet_key = get_wallet_signing_key(
                wallet_name=args.wallet_name,
                derivation_path=args.path,
                password=args.password,
                wallet_file=default_wallet_file(args.datadir, args.network),
                network=args.network,
            )
        except WalletError as exc:
            args.parser.error(str(exc))
        if wallet_key["address_type"] not in ("P2PKH", "P2WPKH"):
            args.parser.error(
                "wallet message signing currently supports only issued "
                "P2PKH and P2WPKH paths"
            )
        private_key_hex = wallet_key["private_key_hex"]
        source = "wallet"

    try:
        result = bitcoin_sign_message(private_key_hex, args.message)
    except MessageSignatureError as exc:
        args.parser.error(str(exc))

    print("source                       :", source)
    if wallet_key is not None:
        print("wallet name                  :", wallet_key["wallet_name"])
        print("derivation path              :", wallet_key["derivation_path"])
        print("selected wallet address      :", wallet_key["address"])
        print("selected wallet address type :", wallet_key["address_type"])
    print("message                      :", result["message"])
    print("compressed public key        :", result["public_key_compressed"])
    print("legacy address               :", result["legacy"]["address"])
    print("legacy format                :", "Bitcoin Core compact")
    print("legacy signature DER         :", result["legacy"]["signature_der"])
    print("legacy signature Base64      :", result["legacy"]["signature_base64"])
    print("P2WPKH address               :", result["p2wpkh"]["address"])
    print("P2WPKH format                :", "BIP322 simple")
    print("P2WPKH signature DER         :", result["p2wpkh"]["signature_der"])
    print("P2WPKH signature Base64      :", result["p2wpkh"]["signature_base64"])


def cmd_bitcoin_verify_message(args):
    if args.network != NETWORK_MAINNET:
        args.parser.error("bitcoin message verification currently supports mainnet only")
    if args.legacy_addr is not None:
        address = args.legacy_addr
        signature_format = "Bitcoin Core compact"
        valid = verify_legacy_message(address, args.message, args.sign)
    else:
        address = args.p2wpkh_addr
        signature_format = "BIP322 simple"
        valid = verify_p2wpkh_message(address, args.message, args.sign)

    print("address      :", address)
    print("format       :", signature_format)
    print("verification :", "success" if valid else "failed")


def cmd_createwallet(args):
    try:
        result = create_wallet(
            wallet_name=args.wallet_name,
            password=args.password,
            entropy_hex=args.entropy_hex,
            mnemonic=args.mnemonic,
            wallet_file=default_wallet_file(args.datadir, args.network),
            network=args.network,
        )
    except WalletError as exc:
        args.parser.error(str(exc))

    if not result["encrypted"]:
        print(
            "WARNING: mnemonic is stored without encryption. "
            "This is dangerous and intended for experiments only.",
            file=sys.stderr,
        )
    print("wallet name :", result["wallet_name"])
    print("network     :", result["network"])
    if result["mnemonic"] is not None:
        print("mnemonic    :", result["mnemonic"])
    print("encrypted   :", "yes" if result["encrypted"] else "no")
    print("accounts    :", result["account_count"])
    print("wallet file :", result["wallet_file"])


def cmd_convert(args):
    try:
        if args.entropy_hex is not None:
            mnemonic = mnemonic_from_entropy_hex(args.entropy_hex)
            print("entropy hex :", args.entropy_hex.lower())
            print("mnemonic    :", mnemonic)
        else:
            entropy_hex = entropy_hex_from_mnemonic(args.mnemonic)
            print("mnemonic    :", " ".join(args.mnemonic.strip().split()))
            print("entropy hex :", entropy_hex)
    except WalletError as exc:
        args.parser.error(str(exc))


def cmd_getnewaddress(args):
    try:
        result = get_new_address(
            wallet_name=args.wallet_name,
            wallet_file=default_wallet_file(args.datadir, args.network),
            change=args.change,
            address_type=args.address_type,
            network=args.network,
        )
    except WalletError as exc:
        args.parser.error(str(exc))

    print("wallet name     :", result["wallet_name"])
    print("network         :", result["network"])
    print("account id      :", result["account_id"])
    print("address         :", result["address"])
    print("address type    :", result["address_type"])
    print("address purpose :", result["purpose"])
    print("branch          :", result["branch"])
    print("address index   :", result["index"])
    print("relative path   :", result["relative_derivation_path"])
    print("derivation path :", result["derivation_path"])


def cmd_getmnemonic(args):
    try:
        result = get_mnemonic(
            wallet_name=args.wallet_name,
            password=args.password,
            wallet_file=default_wallet_file(args.datadir, args.network),
            network=args.network,
        )
    except WalletError as exc:
        args.parser.error(str(exc))

    print("wallet name :", result["wallet_name"])
    print("network     :", args.network)
    print("mnemonic    :", result["mnemonic"])


def cmd_rebuildaddressbook(args):
    try:
        result = rebuild_address_book(
            wallet_name=args.wallet_name,
            wallet_file=default_wallet_file(args.datadir, args.network),
            address_type=args.address_type,
            network=args.network,
        )
    except WalletError as exc:
        args.parser.error(str(exc))

    print("wallet name       :", result["wallet_name"])
    print("network           :", args.network)
    print("account count     :", result["account_count"])
    print("address count     :", result["address_count"])
    print("recovered entries :", result["recovered_count"])
    print("wallet file       :", result["wallet_file"])


def cmd_exportxpub(args):
    try:
        result = export_account_xpub(
            wallet_name=args.wallet_name,
            password=args.password,
            wallet_file=default_wallet_file(args.datadir, args.network),
            address_type=args.address_type,
            network=args.network,
        )
    except WalletError as exc:
        args.parser.error(str(exc))

    print("wallet name     :", result["wallet_name"])
    print("network         :", args.network)
    print("account id      :", result["account_id"])
    print("standard        :", result["standard"])
    print("address type    :", result["address_type"])
    print("account path    :", result["account_derivation_path"])
    print("account xpub    :", result["account_xpub"])
    print("descriptor-like :", result["descriptor_like"])


def cmd_derivepub(args):
    try:
        if args.type.lower() != "p2wpkh":
            args.parser.error("only p2wpkh derivation is currently supported")
        address = derive_p2wpkh_from_account_xpub(
            args.xpub,
            args.branch,
            args.index,
            args.network,
        )
    except WalletError as exc:
        args.parser.error(str(exc))

    print("address type :", "P2WPKH")
    print("network      :", args.network)
    print("branch       :", args.branch)
    print("index        :", args.index)
    print("relative path:", f"m/{args.branch}/{args.index}")
    print("address      :", address)


def _format_btc(satoshis: int) -> str:
    return f"{Decimal(satoshis) / Decimal(100_000_000):.8f} BTC"


def _runtime_error(exc: Exception) -> None:
    print(f"error: {exc}", file=sys.stderr)
    raise SystemExit(1)


def cmd_syncwallet(args):
    try:
        result = sync_wallet(
            wallet_name=args.wallet_name,
            wallet_file=default_wallet_file(args.datadir, args.network),
            cache_file=default_wallet_cache_file(args.datadir, args.network),
            backend=EsploraBackend(
                args.backend_url,
                args.timeout,
                network=args.network,
                retries=args.retries,
            ),
            include_transactions=not args.no_transactions,
            network=args.network,
        )
    except (WalletError, EsploraError) as exc:
        _runtime_error(exc)

    balance = result["balance"]
    print("wallet name        :", result["wallet_name"])
    print("network            :", args.network)
    print("synced at          :", result["synced_at"])
    print("backend            :", result["backend"]["base_url"])
    print("tip height         :", result["tip"]["height"])
    print("tip hash           :", result["tip"]["hash"])
    print("address count      :", result["address_count"])
    print("used address count :", result["used_address_count"])
    print("utxo count         :", len(result["utxos"]))
    print("transaction count  :", len(result["transactions"]))
    print("confirmed balance  :", balance["confirmed"], "sats", f"({_format_btc(balance['confirmed'])})")
    print("unconfirmed balance:", balance["unconfirmed"], "sats", f"({_format_btc(balance['unconfirmed'])})")
    print("total balance      :", balance["total"], "sats", f"({_format_btc(balance['total'])})")
    print("cache file         :", result["cache_file"])


def cmd_gettransactionstatus(args):
    """Print the current Esplora confirmation state for one TXID."""

    try:
        status = EsploraBackend(
            args.backend_url,
            args.timeout,
            network=args.network,
            retries=args.retries,
        ).get_transaction_status(args.txid)
    except EsploraError as exc:
        _runtime_error(exc)

    print("txid        :", args.txid.lower())
    print("network     :", args.network)
    print("confirmed   :", status["confirmed"])
    print("block height:", status.get("block_height"))
    print("block hash  :", status.get("block_hash"))
    print("block time  :", status.get("block_time"))


def cmd_getbalance(args):
    try:
        result = get_cached_balance(
            wallet_name=args.wallet_name,
            cache_file=default_wallet_cache_file(args.datadir, args.network),
            network=args.network,
        )
    except WalletError as exc:
        args.parser.error(str(exc))

    balance = result["balance"]
    print("wallet name        :", result["wallet_name"])
    print("network            :", args.network)
    print("synced at          :", result["synced_at"])
    print("tip height         :", result.get("tip", {}).get("height"))
    print("confirmed balance  :", balance["confirmed"], "sats", f"({_format_btc(balance['confirmed'])})")
    print("unconfirmed balance:", balance["unconfirmed"], "sats", f"({_format_btc(balance['unconfirmed'])})")
    print("total balance      :", balance["total"], "sats", f"({_format_btc(balance['total'])})")
    print("cache file         :", result["cache_file"])


def cmd_listunspent(args):
    if args.min_confirmations < 0:
        args.parser.error("--min-confirmations must not be negative")
    try:
        result = list_cached_unspent(
            wallet_name=args.wallet_name,
            cache_file=default_wallet_cache_file(args.datadir, args.network),
            network=args.network,
        )
    except WalletError as exc:
        args.parser.error(str(exc))

    min_confirmations = args.min_confirmations
    utxos = [
        utxo
        for utxo in result["utxos"]
        if int(utxo.get("confirmations", 0)) >= min_confirmations
    ]
    print("wallet name :", result["wallet_name"])
    print("network     :", args.network)
    print("synced at   :", result["synced_at"])
    print("utxo count  :", len(utxos))
    for utxo in utxos:
        print()
        print("txid         :", utxo["txid"])
        print("vout         :", utxo["vout"])
        print("value        :", utxo["value"], "sats", f"({_format_btc(utxo['value'])})")
        print("confirmed    :", "yes" if utxo.get("confirmed") else "no")
        print("confirmations:", utxo.get("confirmations", 0))
        print("address      :", utxo["address"])
        print("account id   :", utxo["account_id"])
        print("address type :", utxo["address_type"])
        print("path         :", utxo["path"])
        print("scriptPubKey :", utxo["script_pubkey"])


def cmd_listtransactions(args):
    if args.limit < 0:
        args.parser.error("--limit must not be negative")
    try:
        result = list_cached_transactions(
            wallet_name=args.wallet_name,
            cache_file=default_wallet_cache_file(args.datadir, args.network),
            network=args.network,
        )
    except WalletError as exc:
        args.parser.error(str(exc))

    transactions = result["transactions"][: args.limit]
    print("wallet name        :", result["wallet_name"])
    print("network            :", args.network)
    print("synced at          :", result["synced_at"])
    print("transaction count  :", len(result["transactions"]))
    print("displayed count    :", len(transactions))
    print("complete history   :", "yes" if result["transactions_complete"] else "no")
    for tx in transactions:
        print()
        print("txid         :", tx["txid"])
        print("direction    :", tx["direction"])
        print("net          :", tx["net"], "sats", f"({_format_btc(tx['net'])})")
        print("received     :", tx["received"], "sats", f"({_format_btc(tx['received'])})")
        print("sent         :", tx["sent"], "sats", f"({_format_btc(tx['sent'])})")
        print("fee          :", tx["fee"], "sats", f"({_format_btc(tx['fee'])})")
        print("confirmed    :", "yes" if tx.get("confirmed") else "no")
        print("confirmations:", tx.get("confirmations", 0))
        print("account ids  :", ", ".join(tx.get("account_ids", [])))
        print("address types:", ", ".join(tx.get("address_types", [])))
        print("addresses    :", ", ".join(tx.get("addresses", [])))


MAX_TRANSACTION_INPUT_FILE_SIZE = 10 * 1024 * 1024


def _read_json_array(path_value: str, description: str) -> list:
    path = Path(path_value)
    try:
        if path.stat().st_size > MAX_TRANSACTION_INPUT_FILE_SIZE:
            raise TransactionError(f"{description} file is too large")
        with path.open("r", encoding="utf-8") as file:
            value = json.load(file)
    except TransactionError:
        raise
    except (OSError, json.JSONDecodeError) as exc:
        raise TransactionError(f'cannot read {description} file "{path}": {exc}') from exc
    if not isinstance(value, list):
        raise TransactionError(f"{description} file must contain a JSON array")
    return value


def _read_raw_transaction_argument(args) -> str:
    if getattr(args, "raw_tx_hex", None) is not None:
        return args.raw_tx_hex.strip()
    path = Path(args.raw_tx_file)
    try:
        if path.stat().st_size > MAX_TRANSACTION_INPUT_FILE_SIZE:
            raise TransactionError("raw transaction file is too large")
        return path.read_text(encoding="ascii").strip()
    except TransactionError:
        raise
    except (OSError, UnicodeError) as exc:
        raise TransactionError(f'cannot read raw transaction file "{path}": {exc}') from exc


def _transaction_template_from_args(args):
    inputs = []
    for value in args.input or []:
        txid, vout = parse_outpoint(value)
        inputs.append({"txid": txid, "vout": vout})
    if args.inputs_file:
        inputs.extend(_read_json_array(args.inputs_file, "inputs"))

    outputs = []
    for value in args.output or []:
        address, amount_sats = parse_output_spec(value)
        outputs.append({"address": address, "amount_sats": amount_sats})
    if args.outputs_file:
        outputs.extend(_read_json_array(args.outputs_file, "outputs"))
    return create_raw_transaction(
        inputs,
        outputs,
        args.network,
        locktime=args.locktime,
        version=args.tx_version,
    )


def cmd_createrawtransaction(args):
    try:
        tx = _transaction_template_from_args(args)
        raw_hex = serialize_transaction_hex(tx, include_witness=False)
        decoded = decode_transaction(tx, args.network)
    except TransactionError as exc:
        args.parser.error(str(exc))
    print("raw transaction hex:", raw_hex)
    print("unsigned txid       :", decoded["txid"])
    print("size                :", decoded["size"], "bytes")
    print("input count         :", decoded["input_count"])
    print("output count        :", decoded["output_count"])


def cmd_decoderawtransaction(args):
    try:
        raw_hex = _read_raw_transaction_argument(args)
        decoded = decode_transaction(
            deserialize_transaction_hex(raw_hex),
            args.network,
        )
    except TransactionError as exc:
        args.parser.error(str(exc))
    print(json.dumps(decoded, indent=2))


def _sync_for_funding(args, wallet_file: Path, cache_file: Path) -> tuple[str, EsploraBackend | None]:
    if args.cache_only:
        return "local cache", None
    backend = EsploraBackend(
        args.backend_url,
        args.timeout,
        network=args.network,
        retries=args.retries,
    )
    sync_wallet(
        wallet_name=args.wallet_name,
        wallet_file=wallet_file,
        cache_file=cache_file,
        backend=backend,
        include_transactions=False,
        network=args.network,
    )
    return "fresh backend synchronization", backend


def _funding_fee_rate(args, backend: EsploraBackend | None) -> str:
    if args.fee_rate_sat_vb is not None:
        return args.fee_rate_sat_vb
    if args.cache_only:
        raise TransactionError(
            "--confirmation-target requires backend access; use --fee-rate-sat-vb with --cache-only"
        )
    if args.confirmation_target <= 0:
        raise TransactionError("--confirmation-target must be greater than zero")
    if backend is None:
        raise TransactionError("fee estimation backend is unavailable")
    estimates = backend.get_fee_estimates()
    target = args.confirmation_target
    estimates_by_target = {
        int(key): rate
        for key, rate in estimates.items()
        if key.isdigit() and int(key) > 0
    }
    available = sorted(estimates_by_target)
    if not estimates_by_target:
        raise TransactionError("backend returned no usable fee estimates")
    selected_target = next((item for item in available if item >= target), available[-1])
    return format(estimates_by_target[selected_target], "f")


def _default_transaction_document_path(prefix: str, identifier: str) -> Path:
    return Path.cwd() / f"{prefix}-{identifier}.json"


def cmd_fundrawtransaction(args):
    wallet_file = default_wallet_file(args.datadir, args.network)
    cache_file = default_wallet_cache_file(args.datadir, args.network)
    try:
        tx = deserialize_transaction_hex(_read_raw_transaction_argument(args))
        utxo_source, backend = _sync_for_funding(args, wallet_file, cache_file)
        fee_rate = _funding_fee_rate(args, backend)
        document = fund_transaction(
            tx,
            args.wallet_name,
            wallet_file,
            cache_file,
            args.network,
            args.address_type,
            fee_rate,
            min_confirmations=args.min_confirmations,
            include_outpoints=args.include_utxo,
            exclude_outpoints=set(args.exclude_utxo or []),
            max_fee_sats=args.max_fee_sats,
            max_cache_age_seconds=args.max_cache_age_seconds,
            utxo_source=utxo_source,
        )
        output_file = (
            Path(args.output_file)
            if args.output_file
            else _default_transaction_document_path("funded", document["draft_id"])
        )
        save_json_document(document, output_file)
    except (TransactionError, WalletError, EsploraError) as exc:
        _runtime_error(exc)

    change = next((item for item in document["outputs"] if item["is_change"]), None)
    print("draft id             :", document["draft_id"])
    print("UTXO source           :", document["utxo_source"])
    print("selected input count  :", len(document["inputs"]))
    print("total input           :", document["total_input_sats"], "sats")
    print("destination total     :", document["destination_total_sats"], "sats")
    print("estimated fee         :", document["estimated_fee_sats"], "sats")
    print("estimated vsize       :", document["estimated_vsize"], "vB")
    print("requested fee rate    :", document["requested_fee_rate_sat_vb"], "sat/vB")
    print("change value          :", change["value"] if change else 0, "sats")
    print("change address        :", change["address"] if change else "none")
    print("change output position:", document["change_position"])
    print("output file           :", output_file.resolve())


def _wallet_signing_password(args, wallet_file: Path) -> str | None:
    try:
        encrypted = wallet_requires_password(
            args.wallet_name,
            wallet_file,
            network=args.network,
        )
    except WalletError:
        raise
    password = getattr(args, "password", None)
    if password is not None:
        print(
            "warning: --password can be exposed through shell history and process listings",
            file=sys.stderr,
        )
        return password
    if encrypted:
        return getpass.getpass("wallet password: ")
    return None


def cmd_signrawtransactionwithwallet(args):
    wallet_file = default_wallet_file(args.datadir, args.network)
    cache_file = default_wallet_cache_file(args.datadir, args.network)
    try:
        document = load_json_document(Path(args.transaction_file))
        password = _wallet_signing_password(args, wallet_file)
        signed = sign_funded_transaction(
            document,
            args.wallet_name,
            password,
            wallet_file,
            cache_file,
            args.network,
            max_fee_sats=args.max_fee_sats,
        )
        output_file = (
            Path(args.output_file)
            if args.output_file
            else Path(args.transaction_file).with_suffix(".signed.json")
        )
        save_json_document(signed, output_file)
    except (TransactionError, WalletError) as exc:
        _runtime_error(exc)
    print("complete          : yes")
    print("txid              :", signed["txid"])
    print("wtxid             :", signed["wtxid"])
    print("signed input count:", signed["signed_input_count"])
    print("vsize             :", signed["vsize"], "vB")
    print("fee               :", signed["fee_sats"], "sats")
    print("fee rate          :", signed["fee_rate_sat_vb"], "sat/vB")
    print("output file       :", output_file.resolve())
    print("hex               :", signed["hex"])


def _confirm_broadcast(
    args,
    txid: str,
    backend_url: str,
    document: dict | None = None,
) -> None:
    if args.network == NETWORK_MAINNET and not args.allow_mainnet:
        raise TransactionError(
            "mainnet broadcasting is disabled unless --allow-mainnet is supplied"
        )
    print("network:", args.network)
    print("backend:", backend_url)
    print("txid   :", txid)
    if document is not None:
        destination_total = sum(
            item["value"] for item in document.get("outputs", []) if not item.get("is_change")
        )
        print("destination total:", destination_total, "sats")
        print("input total      :", sum(item["value"] for item in document["inputs"]), "sats")
        print("output total     :", sum(item["value"] for item in document["outputs"]), "sats")
        print("fee              :", document.get("fee_sats"), "sats")
        print("fee rate         :", document.get("fee_rate_sat_vb"), "sat/vB")
        print("vsize            :", document.get("vsize"), "vB")
        for item in document["outputs"]:
            label = "change" if item.get("is_change") else "destination"
            print(f"{label} output:", item.get("address"), item["value"], "sats")
    if args.yes:
        return
    try:
        answer = input('Broadcast this transaction? Type "yes" to continue: ').strip()
    except EOFError as exc:
        raise TransactionError("broadcast confirmation requires interactive input or --yes") from exc
    if answer != "yes":
        raise TransactionError("broadcast cancelled")


def _broadcast_document(args, document: dict) -> dict:
    preview_tx, _ = validate_signed_document(document, args.network)
    preview = transaction_metrics(preview_tx)
    backend = EsploraBackend(
        args.backend_url,
        args.timeout,
        network=args.network,
        retries=args.retries,
    )
    _confirm_broadcast(args, preview["txid"], backend.base_url, document)
    return broadcast_signed_transaction(
        document,
        args.network,
        backend,
        cache_file=default_wallet_cache_file(args.datadir, args.network),
        max_fee_sats=args.max_fee_sats,
    )


def cmd_sendrawtransaction(args):
    try:
        if args.transaction_file:
            document = load_json_document(Path(args.transaction_file))
            result = _broadcast_document(args, document)
        else:
            raw_hex = _read_raw_transaction_argument(args)
            tx = deserialize_transaction_hex(raw_hex)
            if not tx.inputs or not tx.outputs:
                raise TransactionError("transaction must contain at least one input and one output")
            if any(not item.script_sig and not item.witness for item in tx.inputs):
                raise TransactionError("raw transaction contains an input with no unlocking data")
            if args.max_fee_sats is not None:
                raise TransactionError(
                    "--max-fee-sats requires --transaction-file with prevout metadata"
                )
            metrics = transaction_metrics(tx)
            backend = EsploraBackend(
                args.backend_url,
                args.timeout,
                network=args.network,
                retries=args.retries,
            )
            _confirm_broadcast(args, metrics["txid"], backend.base_url)
            backend.verify_network()
            remote_txid = backend.broadcast_transaction(raw_hex)
            if remote_txid != metrics["txid"]:
                raise TransactionError("backend transaction id does not match local txid")
            result = {**metrics, "backend": backend.base_url}
            print(
                "warning: raw hex has no prevout metadata; signatures and fee could not be verified locally",
                file=sys.stderr,
            )
    except (TransactionError, EsploraError, WalletError) as exc:
        _runtime_error(exc)
    print("broadcast accepted:", result["txid"])
    print("network           :", args.network)
    print("backend           :", result["backend"])
    if result.get("cache_warning"):
        print("cache warning     :", result["cache_warning"], file=sys.stderr)


def cmd_sendtoaddress(args):
    wallet_file = default_wallet_file(args.datadir, args.network)
    cache_file = default_wallet_cache_file(args.datadir, args.network)
    try:
        template = create_raw_transaction(
            [],
            [{"address": args.address, "amount_sats": args.amount_sats}],
            args.network,
        )
        utxo_source, backend = _sync_for_funding(args, wallet_file, cache_file)
        fee_rate = _funding_fee_rate(args, backend)
        funded = fund_transaction(
            template,
            args.wallet_name,
            wallet_file,
            cache_file,
            args.network,
            args.address_type,
            fee_rate,
            min_confirmations=args.min_confirmations,
            include_outpoints=args.include_utxo,
            exclude_outpoints=set(args.exclude_utxo or []),
            max_fee_sats=args.max_fee_sats,
            max_cache_age_seconds=args.max_cache_age_seconds,
            utxo_source=utxo_source,
        )
        password = _wallet_signing_password(args, wallet_file)
        signed = sign_funded_transaction(
            funded,
            args.wallet_name,
            password,
            wallet_file,
            cache_file,
            args.network,
            max_fee_sats=args.max_fee_sats,
        )
        output_file = (
            Path(args.output_file)
            if args.output_file
            else _default_transaction_document_path("signed", funded["draft_id"])
        )
        save_json_document(signed, output_file)
        print("signed transaction :", output_file.resolve())
        if args.dry_run:
            print("dry run            : transaction was not broadcast")
            print("change issued      :", "yes" if signed["change_position"] is not None else "no")
            print("txid               :", signed["txid"])
            print("fee                :", signed["fee_sats"], "sats")
            print("hex                :", signed["hex"])
            return
        result = _broadcast_document(args, signed)
    except (TransactionError, WalletError, EsploraError) as exc:
        _runtime_error(exc)
    print("broadcast accepted:", result["txid"])
    print("amount            :", args.amount_sats, "sats")
    print("fee               :", signed["fee_sats"], "sats")
    print("change position   :", signed["change_position"])
    print("network           :", args.network)
    if result.get("cache_warning"):
        print("cache warning     :", result["cache_warning"], file=sys.stderr)


def cmd_sendall(args):
    wallet_file = default_wallet_file(args.datadir, args.network)
    cache_file = default_wallet_cache_file(args.datadir, args.network)
    try:
        utxo_source, backend = _sync_for_funding(args, wallet_file, cache_file)
        fee_rate = _funding_fee_rate(args, backend)
        funded = fund_all_transaction(
            args.address,
            args.wallet_name,
            cache_file,
            args.network,
            args.address_type,
            fee_rate,
            min_confirmations=args.min_confirmations,
            exclude_outpoints=set(args.exclude_utxo or []),
            max_fee_sats=args.max_fee_sats,
            max_cache_age_seconds=args.max_cache_age_seconds,
            utxo_source=utxo_source,
        )
        password = _wallet_signing_password(args, wallet_file)
        signed = sign_funded_transaction(
            funded,
            args.wallet_name,
            password,
            wallet_file,
            cache_file,
            args.network,
            max_fee_sats=args.max_fee_sats,
            final_fee_limit_message=True,
        )
        output_file = (
            Path(args.output_file)
            if args.output_file
            else _default_transaction_document_path("signed", funded["draft_id"])
        )
        save_json_document(signed, output_file)
        print("signed transaction :", output_file.resolve())
        if args.dry_run:
            print("dry run            : transaction was not broadcast")
            print("txid               :", signed["txid"])
            print("amount             :", signed["outputs"][0]["value"], "sats")
            print("fee               :", signed["fee_sats"], "sats")
            print("hex               :", signed["hex"])
            return
        result = _broadcast_document(args, signed)
    except (TransactionError, WalletError, EsploraError) as exc:
        _runtime_error(exc)
    print("broadcast accepted:", result["txid"])
    print("amount            :", signed["outputs"][0]["value"], "sats")
    print("fee               :", signed["fee_sats"], "sats")
    print("input count       :", len(signed["inputs"]))
    print("change position   :", signed["change_position"])
    print("network           :", args.network)
    if result.get("cache_warning"):
        print("cache warning     :", result["cache_warning"], file=sys.stderr)


SHELL_BUILTIN_COMMANDS = {
    "exit": "Exit the interactive shell.",
    "quit": "Exit the interactive shell.",
    "help": "Show shell or command help.",
}


def _find_subparsers_action(parser: argparse.ArgumentParser):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action
    return None


@lru_cache(maxsize=1)
def _shell_completion_index() -> tuple[dict[str, argparse.ArgumentParser], dict[str, list[str]]]:
    parser = build_parser()
    subparsers_action = _find_subparsers_action(parser)
    if subparsers_action is None:
        return {}, {}

    command_parsers = dict(subparsers_action.choices)
    options_by_command = {}
    for command, command_parser in command_parsers.items():
        options = []
        for action in command_parser._actions:
            if action.help == argparse.SUPPRESS:
                continue
            options.extend(action.option_strings)
        options_by_command[command] = sorted(options)
    return command_parsers, options_by_command


def _split_completion_arguments(text: str) -> list[str]:
    try:
        return shlex.split(text, posix=False)
    except ValueError:
        return text.split()


def _current_completion_prefix(text_before_cursor: str) -> str:
    if not text_before_cursor or text_before_cursor[-1].isspace():
        return ""
    return text_before_cursor.rsplit(maxsplit=1)[-1]


def _shell_option_matches(command: str, prefix: str) -> list[str]:
    _, options_by_command = _shell_completion_index()
    return [
        option
        for option in options_by_command.get(command, [])
        if option.startswith(prefix)
    ]


def _shell_command_matches(prefix: str) -> list[str]:
    command_parsers, _ = _shell_completion_index()
    commands = sorted(
        [
            command
            for command in [*command_parsers, *SHELL_BUILTIN_COMMANDS]
            if command != "shell"
        ]
    )
    return [command for command in commands if command.startswith(prefix)]


def _print_shell_help(command: str | None = None) -> None:
    command_parsers, _ = _shell_completion_index()
    if command:
        if command in command_parsers:
            command_parsers[command].print_help()
            return
        if command in SHELL_BUILTIN_COMMANDS:
            print(f"{command}: {SHELL_BUILTIN_COMMANDS[command]}")
            return
        print(f'unknown command: "{command}"', file=sys.stderr)
        return

    print("Available commands:")
    help_by_command = {}
    subparser_action = _find_subparsers_action(build_parser())
    if subparser_action is not None:
        help_by_command = {
            choice_action.dest: choice_action.help
            for choice_action in subparser_action._choices_actions
        }
    for name in sorted(command for command in command_parsers if command != "shell"):
        print(f"  {name:<20} {help_by_command.get(name, '')}")
    for name, help_text in SHELL_BUILTIN_COMMANDS.items():
        print(f"  {name:<20} {help_text}")
    print('\nUse "help <command>" for command-specific options.')


class BitcoinToolCompleter(Completer):
    def get_completions(self, document, complete_event):
        text_before_cursor = document.text_before_cursor
        stripped = text_before_cursor.lstrip()
        prefix = _current_completion_prefix(text_before_cursor)
        words = _split_completion_arguments(stripped)

        completing_first_token = (
            not words
            or (len(words) == 1 and not text_before_cursor[-1:].isspace())
        )
        if completing_first_token:
            for command in _shell_command_matches(prefix):
                yield Completion(command, start_position=-len(prefix))
            return

        command = words[0]
        if command == "help":
            for candidate in _shell_command_matches(prefix):
                yield Completion(candidate, start_position=-len(prefix))
            return

        for option in _shell_option_matches(command, prefix):
            yield Completion(option, start_position=-len(prefix))


class BitcoinToolLexer(Lexer):
    _token_pattern = re.compile(r"\s+|\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'|\S+")
    _hex_pattern = re.compile(r"(?:0x)?[0-9a-fA-F]{16,}")
    _number_pattern = re.compile(r"\d+")

    def lex_document(self, document):
        command_parsers, _ = _shell_completion_index()

        def get_line(lineno: int):
            try:
                line = document.lines[lineno]
            except IndexError:
                return []

            fragments = []
            command_seen = False
            for match in self._token_pattern.finditer(line):
                token = match.group(0)
                if token.isspace():
                    fragments.append(("", token))
                    continue

                if not command_seen:
                    style = (
                        "class:command"
                        if token in command_parsers or token in SHELL_BUILTIN_COMMANDS
                        else "class:error"
                    )
                    command_seen = True
                elif token.startswith("-"):
                    style = "class:option"
                elif token.startswith(("\"", "'")):
                    style = "class:string"
                elif self._number_pattern.fullmatch(token):
                    style = "class:number"
                elif self._hex_pattern.fullmatch(token):
                    style = "class:hex"
                else:
                    style = "class:value"
                fragments.append((style, token))
            return fragments

        return get_line


def _run_prompt_toolkit_shell(network: str) -> None:
    style = Style.from_dict(
        {
            "prompt": "ansigreen bold",
            "command": "ansicyan bold",
            "option": "ansigreen",
            "string": "ansiblue",
            "number": "ansiyellow",
            "hex": "ansimagenta",
            "value": "ansiwhite",
            "error": "ansired",
        }
    )
    session = PromptSession(
        lexer=BitcoinToolLexer(),
        completer=BitcoinToolCompleter(),
        complete_while_typing=True,
        style=style,
    )
    print("Bitcoin Tool interactive shell")
    print("Powered by Wen Zhongzhi")
    print("Network:", network)
    print('Type "help" to show commands and "exit" to quit.')
    prompt_text = (
        "bitcoin-tool"
        if network == NETWORK_MAINNET
        else f"bitcoin-tool[{network}]"
    )

    while True:
        try:
            command_line = session.prompt(HTML(f"<prompt>{prompt_text}&gt; </prompt>"))
        except (EOFError, KeyboardInterrupt):
            print()
            break

        stripped = command_line.strip()
        if not stripped:
            continue

        arguments = _split_shell_arguments(stripped)
        if arguments is None:
            continue

        command = arguments[0]
        command_arguments = arguments[1:]
        if command in {"exit", "quit"}:
            break
        if command == "help":
            _print_shell_help(command_arguments[0] if command_arguments else None)
            continue
        if command == "shell":
            print("already in interactive shell", file=sys.stderr)
            continue

        try:
            run_cli(["--network", network, command, *command_arguments])
        except SystemExit:
            pass


def _split_shell_arguments(argument_line: str) -> list[str] | None:
    """
    Split an interactive command line into argparse-compatible arguments.

    posix=False is used so Windows paths such as D:\\wallets are not
    interpreted as strings containing escape characters.
    """
    try:
        arguments = shlex.split(argument_line, posix=False)
    except ValueError as exc:
        print(f"invalid command line: {exc}", file=sys.stderr)
        return None

    # With posix=False, shlex preserves surrounding quotation marks.
    # Remove one pair so argparse receives my_BTC_001 instead of
    # "my_BTC_001".
    normalized_arguments = []

    for argument in arguments:
        if (
            len(argument) >= 2
            and argument[0] == argument[-1]
            and argument[0] in {'"', "'"}
        ):
            argument = argument[1:-1]

        normalized_arguments.append(argument)

    return normalized_arguments


class BitcoinToolShell(cmd.Cmd):
    intro = (
        "Bitcoin Tool interactive shell\n"
        "Powered by Wen Zhongzhi\n"
        'Type "help" to show commands and "exit" to quit.'
    )
    prompt = "bitcoin-tool> "

    def __init__(self, network: str = NETWORK_MAINNET):
        super().__init__()
        self.network = network
        if network != NETWORK_MAINNET:
            self.prompt = f"bitcoin-tool[{network}]> "

    def __getattr__(self, name: str):
        if name.startswith(("do_", "complete_")) and "-" in name:
            return object.__getattribute__(self, name.replace("-", "_"))
        raise AttributeError(name)

    def emptyline(self) -> None:
        # cmd.Cmd normally repeats the previous command on an empty line.
        # For a wallet tool, doing nothing is safer.
        pass

    def _run_command(self, command: str, argument_line: str) -> None:
        arguments = _split_shell_arguments(argument_line)

        if arguments is None:
            return

        try:
            run_cli(["--network", self.network, command, *arguments])
        except SystemExit:
            # argparse uses SystemExit for --help and argument errors.
            # Do not exit the interactive shell.
            pass

    def _complete_options(self, command: str, text: str) -> list[str]:
        return _shell_option_matches(command, text)

    def completenames(self, text: str, *ignored) -> list[str]:
        return [f"{command} " for command in _shell_command_matches(text)]

    def do_help(self, argument_line: str) -> None:
        arguments = _split_shell_arguments(argument_line)
        if arguments is None:
            return
        _print_shell_help(arguments[0] if arguments else None)

    def do_hash(self, argument_line: str) -> None:
        """Hash an ASCII string, hexadecimal string, or file."""
        self._run_command("hash", argument_line)

    def complete_hash(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("hash", text)

    def do_gen(self, argument_line: str) -> None:
        """Generate a random 32-byte private key."""
        self._run_command("gen", argument_line)

    def do_addr(self, argument_line: str) -> None:
        """Generate Bitcoin addresses from a private or public key."""
        self._run_command("addr", argument_line)

    def complete_addr(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("addr", text)

    def do_ecdsa_sign(self, argument_line: str) -> None:
        """Sign a message with raw ECDSA over secp256k1."""
        self._run_command("ecdsa-sign", argument_line)

    def complete_ecdsa_sign(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("ecdsa-sign", text)

    def do_ecdsa_verify(self, argument_line: str) -> None:
        """Verify a raw ECDSA message signature."""
        self._run_command("ecdsa-verify", argument_line)

    def complete_ecdsa_verify(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("ecdsa-verify", text)

    def do_bitcoin_sign_message(self, argument_line: str) -> None:
        """Sign a message for P2PKH and P2WPKH addresses."""
        self._run_command("bitcoin-sign-message", argument_line)

    def complete_bitcoin_sign_message(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("bitcoin-sign-message", text)

    def do_bitcoin_verify_message(self, argument_line: str) -> None:
        """Verify a Bitcoin address message signature."""
        self._run_command("bitcoin-verify-message", argument_line)

    def complete_bitcoin_verify_message(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("bitcoin-verify-message", text)

    def do_createwallet(self, argument_line: str) -> None:
        """Create a multi-account HD wallet."""
        self._run_command("createwallet", argument_line)

    def complete_createwallet(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("createwallet", text)

    def do_convert(self, argument_line: str) -> None:
        """Convert between BIP39 entropy and mnemonic."""
        self._run_command("convert", argument_line)

    def complete_convert(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("convert", text)

    def do_getnewaddress(self, argument_line: str) -> None:
        """Derive the next wallet address."""
        self._run_command("getnewaddress", argument_line)

    def complete_getnewaddress(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("getnewaddress", text)

    def do_getmnemonic(self, argument_line: str) -> None:
        """Display a wallet mnemonic."""
        self._run_command("getmnemonic", argument_line)

    def complete_getmnemonic(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("getmnemonic", text)

    def do_rebuildaddressbook(self, argument_line: str) -> None:
        """Rebuild wallet address metadata."""
        self._run_command("rebuildaddressbook", argument_line)

    def complete_rebuildaddressbook(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("rebuildaddressbook", text)

    def do_exportxpub(self, argument_line: str) -> None:
        """Export a wallet account xpub."""
        self._run_command("exportxpub", argument_line)

    def complete_exportxpub(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("exportxpub", text)

    def do_derivepub(self, argument_line: str) -> None:
        """Derive an address from an account xpub."""
        self._run_command("derivepub", argument_line)

    def complete_derivepub(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("derivepub", text)

    def do_syncwallet(self, argument_line: str) -> None:
        """Sync wallet chain state into the local cache."""
        self._run_command("syncwallet", argument_line)

    def complete_syncwallet(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("syncwallet", text)

    def do_gettransactionstatus(self, argument_line: str) -> None:
        """Query whether one transaction is confirmed."""
        self._run_command("gettransactionstatus", argument_line)

    def complete_gettransactionstatus(
        self, text: str, line: str, begidx: int, endidx: int
    ) -> list[str]:
        return self._complete_options("gettransactionstatus", text)

    def do_getbalance(self, argument_line: str) -> None:
        """Read wallet balance from the local cache."""
        self._run_command("getbalance", argument_line)

    def complete_getbalance(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("getbalance", text)

    def do_listunspent(self, argument_line: str) -> None:
        """List cached wallet UTXOs."""
        self._run_command("listunspent", argument_line)

    def complete_listunspent(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("listunspent", text)

    def do_listtransactions(self, argument_line: str) -> None:
        """List cached wallet transactions."""
        self._run_command("listtransactions", argument_line)

    def complete_listtransactions(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("listtransactions", text)

    def do_createrawtransaction(self, argument_line: str) -> None:
        """Create an unsigned P2PKH/P2WPKH transaction template."""
        self._run_command("createrawtransaction", argument_line)

    def complete_createrawtransaction(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("createrawtransaction", text)

    def do_fundrawtransaction(self, argument_line: str) -> None:
        """Select wallet UTXOs and add change to a transaction."""
        self._run_command("fundrawtransaction", argument_line)

    def complete_fundrawtransaction(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("fundrawtransaction", text)

    def do_signrawtransactionwithwallet(self, argument_line: str) -> None:
        """Sign a funded transaction with wallet keys."""
        self._run_command("signrawtransactionwithwallet", argument_line)

    def complete_signrawtransactionwithwallet(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("signrawtransactionwithwallet", text)

    def do_decoderawtransaction(self, argument_line: str) -> None:
        """Decode a legacy or SegWit raw transaction."""
        self._run_command("decoderawtransaction", argument_line)

    def complete_decoderawtransaction(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("decoderawtransaction", text)

    def do_sendrawtransaction(self, argument_line: str) -> None:
        """Broadcast a signed transaction through Esplora."""
        self._run_command("sendrawtransaction", argument_line)

    def complete_sendrawtransaction(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("sendrawtransaction", text)

    def do_sendtoaddress(self, argument_line: str) -> None:
        """Fund, sign, and broadcast a wallet payment."""
        self._run_command("sendtoaddress", argument_line)

    def complete_sendtoaddress(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("sendtoaddress", text)

    def do_sendall(self, argument_line: str) -> None:
        """Spend all eligible wallet UTXOs to one address without change."""
        self._run_command("sendall", argument_line)

    def complete_sendall(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        return self._complete_options("sendall", text)

    def do_exit(self, argument_line: str) -> bool:
        """Exit the interactive shell."""
        return True

    def do_quit(self, argument_line: str) -> bool:
        """Exit the interactive shell."""
        return True

    def do_EOF(self, argument_line: str) -> bool:
        """Exit when Ctrl+Z followed by Enter is entered on Windows."""
        print()
        return True

def cmd_shell(args) -> None:
    if PromptSession is not None:
        _run_prompt_toolkit_shell(args.network)
    else:
        BitcoinToolShell(args.network).cmdloop()

def add_wallet_access_arguments(parser):
    parser.add_argument("--wallet-name", required=True, help="wallet name")
    parser.add_argument(
        "--datadir",
        help="wallet data directory (overrides BITCOIN_TOOL_DATADIR)",
    )

def add_raw_transaction_source(parser, *, include_document: bool = False):
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--raw-tx-hex", help="raw transaction hexadecimal string")
    group.add_argument("--raw-tx-file", help="file containing raw transaction hex")
    if include_document:
        group.add_argument(
            "--transaction-file",
            help="signed bitcoin-tool transaction JSON document",
        )


def add_backend_arguments(parser):
    parser.add_argument(
        "--backend-url",
        help="Esplora API base URL (default depends on --network)",
    )
    parser.add_argument("--timeout", type=int, default=20, help="network timeout in seconds")
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="retry transient Esplora GET failures this many times (default: 2)",
    )


def add_funding_arguments(parser, *, include_utxo: bool = True):
    parser.add_argument(
        "--address-type",
        choices=("p2pkh", "p2wpkh"),
        default="p2wpkh",
        help="wallet input type (default: p2wpkh)",
    )
    fee_source = parser.add_mutually_exclusive_group(required=True)
    fee_source.add_argument("--fee-rate-sat-vb", help="exact fee rate in sat/vB")
    fee_source.add_argument(
        "--confirmation-target",
        type=int,
        help="request an Esplora fee estimate for this block target",
    )
    parser.add_argument("--min-confirmations", type=int, default=1)
    if include_utxo:
        parser.add_argument("--include-utxo", action="append", default=[])
    parser.add_argument("--exclude-utxo", action="append", default=[])
    parser.add_argument(
        "--max-fee-sats",
        type=int,
        help="hard maximum total transaction fee in satoshis",
    )
    parser.add_argument(
        "--cache-only",
        action="store_true",
        help="use the local cache without backend synchronization",
    )
    parser.add_argument("--max-cache-age-seconds", type=int, default=300)
    add_backend_arguments(parser)


def add_broadcast_confirmation_arguments(parser):
    parser.add_argument(
        "--allow-mainnet",
        action="store_true",
        help="explicitly enable mainnet broadcast for this invocation",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="skip the interactive broadcast confirmation",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bitcoin_tool",
        description="Bitcoin research CLI tool: hash / keys / address / scripts",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--network",
        choices=SUPPORTED_NETWORKS,
        default=NETWORK_MAINNET,
        help="Bitcoin network for address and wallet operations (default: mainnet)",
    )
    
    sub = parser.add_subparsers(dest="cmd", required=True)

    # hash
    p_hash = sub.add_parser("hash", help="hash a ASCII string, hex string or a file")
    g = p_hash.add_mutually_exclusive_group(required=True)
    g.add_argument("-s", "--string", help="input ASCII string")
    g.add_argument("-x", "--hex", help="input hex string")
    g.add_argument("-f", "--file", help="input file path")

    p_hash.set_defaults(func=cmd_hash, parser=p_hash)

    # gen
    p_gen = sub.add_parser("gen", help="generate random 32-byte private key")
    p_gen.set_defaults(func=cmd_gen)

    # convert
    p_convert = sub.add_parser(
        "convert",
        help="convert between BIP39 entropy hex and mnemonic words",
    )
    convert_input = p_convert.add_mutually_exclusive_group(required=True)
    convert_input.add_argument(
        "--entropy-hex-to-mnemonic",
        dest="entropy_hex",
        help="BIP39 entropy hex: 128, 160, 192, 224, or 256 bits",
    )
    convert_input.add_argument(
        "--mnemonic-to-entropy-hex",
        dest="mnemonic",
        help="BIP39 mnemonic words",
    )
    p_convert.set_defaults(func=cmd_convert, parser=p_convert)
    
    # addr
    p_addr = sub.add_parser("addr", help="private/public key -> Bitcoin addresses")
    addr_input = p_addr.add_mutually_exclusive_group(required=True)
    addr_input.add_argument(
        "--private-key-hex",
        help="32-byte private key hex (64 hex chars)",
    )
    addr_input.add_argument(
        "--public-key-hex",
        help="compressed (33-byte) or uncompressed (65-byte) public key hex",
    )
    #p_addr.add_argument("--testnet", action="store_true", help="use testnet version")#to be implemented in future
    p_addr.set_defaults(func=cmd_addr, parser=p_addr)

    # ecdsa-sign
    p_ecdsa_sign = sub.add_parser(
        "ecdsa-sign",
        help="sign a message with raw ECDSA over secp256k1",
    )
    p_ecdsa_sign.add_argument(
        "--private-key-hex",
        required=True,
        help="32-byte private key hex (64 hex chars)",
    )
    p_ecdsa_sign.add_argument("--message", required=True, help="message text")
    p_ecdsa_sign.set_defaults(func=cmd_ecdsa_sign, parser=p_ecdsa_sign)

    # ecdsa-verify
    p_ecdsa_verify = sub.add_parser(
        "ecdsa-verify",
        help="verify a raw ECDSA message signature",
    )
    p_ecdsa_verify.add_argument(
        "--public-key-hex",
        required=True,
        help="compressed (33-byte) or uncompressed (65-byte) public key hex",
    )
    p_ecdsa_verify.add_argument("--message", required=True, help="message text")
    p_ecdsa_verify.add_argument("--sign", required=True, help="DER signature hex")
    p_ecdsa_verify.set_defaults(func=cmd_ecdsa_verify, parser=p_ecdsa_verify)

    # bitcoin-sign-message
    p_bitcoin_sign = sub.add_parser(
        "bitcoin-sign-message",
        help="sign for a legacy P2PKH address and a P2WPKH address",
    )
    bitcoin_sign_source = p_bitcoin_sign.add_mutually_exclusive_group(required=True)
    bitcoin_sign_source.add_argument(
        "--private-key-hex",
        help="32-byte private key hex; exposed to shell history/process listings",
    )
    bitcoin_sign_source.add_argument(
        "--wallet-name",
        help="wallet containing the issued address path",
    )
    p_bitcoin_sign.add_argument(
        "--path",
        help="issued wallet path, for example m/84'/0'/0'/0/0",
    )
    p_bitcoin_sign.add_argument(
        "--password",
        help="password for an encrypted wallet",
    )
    p_bitcoin_sign.add_argument(
        "--datadir",
        help="wallet data directory (overrides BITCOIN_TOOL_DATADIR)",
    )
    p_bitcoin_sign.add_argument("--message", required=True, help="message text")
    p_bitcoin_sign.set_defaults(func=cmd_bitcoin_sign_message, parser=p_bitcoin_sign)

    # bitcoin-verify-message
    p_bitcoin_verify = sub.add_parser(
        "bitcoin-verify-message",
        help="verify a Bitcoin Core legacy or BIP322 P2WPKH message signature",
    )
    bitcoin_verify_address = p_bitcoin_verify.add_mutually_exclusive_group(required=True)
    bitcoin_verify_address.add_argument(
        "--legacy-addr",
        help="mainnet P2PKH address (1...)",
    )
    bitcoin_verify_address.add_argument(
        "--p2wpkh-addr",
        help="mainnet native SegWit P2WPKH address (bc1q...)",
    )
    p_bitcoin_verify.add_argument(
        "--sign",
        required=True,
        help="Bitcoin Core compact or BIP322 simple Base64 signature",
    )
    p_bitcoin_verify.add_argument("--message", required=True, help="message text")
    p_bitcoin_verify.set_defaults(
        func=cmd_bitcoin_verify_message,
        parser=p_bitcoin_verify,
    )

    # createwallet
    p_createwallet = sub.add_parser(
        "createwallet",
        help="create a multi-account BIP44/49/84/86 wallet",
    )
    p_createwallet.add_argument(
        "--wallet-name",
        required=True,
        help="wallet name (letters, numbers, underscores, and hyphens)",
    )
    wallet_seed_input = p_createwallet.add_mutually_exclusive_group()
    wallet_seed_input.add_argument(
        "--entropy-hex",
        help="optional 256-bit entropy (64 hex characters)",
    )
    wallet_seed_input.add_argument(
        "--mnemonic",
        help="import BIP39 mnemonic words",
    )
    p_createwallet.add_argument(
        "--password",
        help="encrypt the mnemonic with AES-256-GCM",
    )
    p_createwallet.add_argument(
        "--datadir",
        help="wallet data directory (overrides BITCOIN_TOOL_DATADIR)",
    )
    p_createwallet.set_defaults(func=cmd_createwallet, parser=p_createwallet)

    # getnewaddress
    p_getnewaddress = sub.add_parser(
        "getnewaddress",
        help="derive the next receiving or change address",
    )
    add_wallet_access_arguments(p_getnewaddress)
    p_getnewaddress.add_argument(
        "--address-type",
        default=DEFAULT_ADDRESS_TYPE,
        choices=SUPPORTED_ADDRESS_TYPES,
        help="wallet account/address type (default: p2wpkh)",
    )
    p_getnewaddress.add_argument(
        "--change",
        action="store_true",
        help="derive the next change address instead of a receiving address",
    )
    p_getnewaddress.set_defaults(func=cmd_getnewaddress, parser=p_getnewaddress)

    # getmnemonic
    p_getmnemonic = sub.add_parser(
        "getmnemonic",
        help="display a wallet mnemonic; encrypted wallets require a password",
    )
    p_getmnemonic.add_argument("--wallet-name", required=True, help="wallet name")
    p_getmnemonic.add_argument(
        "--password",
        help="password for an encrypted wallet",
    )
    p_getmnemonic.add_argument(
        "--datadir",
        help="wallet data directory (overrides BITCOIN_TOOL_DATADIR)",
    )
    p_getmnemonic.set_defaults(func=cmd_getmnemonic, parser=p_getmnemonic)

    # rebuildaddressbook
    p_rebuildaddressbook = sub.add_parser(
        "rebuildaddressbook",
        help="rebuild issued address metadata from wallet public derivation state",
    )
    add_wallet_access_arguments(p_rebuildaddressbook)
    p_rebuildaddressbook.add_argument(
        "--address-type",
        choices=SUPPORTED_ADDRESS_TYPES,
        help="rebuild only this account; default rebuilds every account",
    )
    p_rebuildaddressbook.set_defaults(
        func=cmd_rebuildaddressbook,
        parser=p_rebuildaddressbook,
    )

    # exportxpub
    p_exportxpub = sub.add_parser(
        "exportxpub",
        help="export an account xpub for a wallet",
    )
    p_exportxpub.add_argument("--wallet-name", required=True, help="wallet name")
    p_exportxpub.add_argument(
        "--password",
        help="password for an encrypted wallet",
    )
    p_exportxpub.add_argument(
        "--datadir",
        help="wallet data directory (overrides BITCOIN_TOOL_DATADIR)",
    )
    p_exportxpub.add_argument(
        "--address-type",
        default=DEFAULT_ADDRESS_TYPE,
        choices=SUPPORTED_ADDRESS_TYPES,
        help="wallet account/address type (default: p2wpkh)",
    )
    p_exportxpub.set_defaults(func=cmd_exportxpub, parser=p_exportxpub)

    # derivepub
    p_derivepub = sub.add_parser(
        "derivepub",
        help="derive a P2WPKH address from an account xpub",
    )
    p_derivepub.add_argument("--xpub", required=True, help="account xpub")
    p_derivepub.add_argument(
        "--type",
        default="p2wpkh",
        choices=["p2wpkh"],
        help="address type",
    )
    p_derivepub.add_argument(
        "--branch",
        type=int,
        default=0,
        choices=[0, 1],
        help="0 for receiving addresses, 1 for change addresses",
    )
    p_derivepub.add_argument("--index", type=int, required=True)
    p_derivepub.set_defaults(func=cmd_derivepub, parser=p_derivepub)

    # syncwallet
    p_syncwallet = sub.add_parser(
        "syncwallet",
        help="sync wallet UTXOs and transactions into the local cache",
    )
    add_wallet_access_arguments(p_syncwallet)
    p_syncwallet.add_argument(
        "--backend-url",
        help="Esplora API base URL (default depends on --network)",
    )
    p_syncwallet.add_argument(
        "--timeout",
        type=int,
        default=20,
        help="network timeout in seconds",
    )
    p_syncwallet.add_argument(
        "--retries",
        type=int,
        default=2,
        help="retry transient Esplora GET failures this many times (default: 2)",
    )
    p_syncwallet.add_argument(
        "--no-transactions",
        action="store_true",
        help="skip transaction history and sync only address stats and UTXOs",
    )
    p_syncwallet.set_defaults(func=cmd_syncwallet, parser=p_syncwallet)

    # gettransactionstatus
    p_transaction_status = sub.add_parser(
        "gettransactionstatus",
        help="query whether one transaction is confirmed",
    )
    p_transaction_status.add_argument(
        "--txid",
        required=True,
        help="64-character transaction ID",
    )
    add_backend_arguments(p_transaction_status)
    p_transaction_status.set_defaults(
        func=cmd_gettransactionstatus,
        parser=p_transaction_status,
    )

    # getbalance
    p_getbalance = sub.add_parser(
        "getbalance",
        help="read wallet balance from the local cache",
    )
    add_wallet_access_arguments(p_getbalance)
    p_getbalance.set_defaults(func=cmd_getbalance, parser=p_getbalance)

    # listunspent
    p_listunspent = sub.add_parser(
        "listunspent",
        help="list cached wallet UTXOs",
    )
    add_wallet_access_arguments(p_listunspent)
    p_listunspent.add_argument(
        "--min-confirmations",
        type=int,
        default=0,
        help="minimum number of confirmations to display",
    )
    p_listunspent.set_defaults(func=cmd_listunspent, parser=p_listunspent)

    # listtransactions
    p_listtransactions = sub.add_parser(
        "listtransactions",
        help="list cached wallet transactions",
    )
    add_wallet_access_arguments(p_listtransactions)
    p_listtransactions.add_argument(
        "--limit",
        type=int,
        default=20,
        help="maximum number of transactions to display",
    )
    p_listtransactions.set_defaults(func=cmd_listtransactions, parser=p_listtransactions)

    # createrawtransaction
    p_create_raw = sub.add_parser(
        "createrawtransaction",
        help="create an unsigned P2PKH/P2WPKH raw transaction",
    )
    p_create_raw.add_argument(
        "--input",
        action="append",
        help='input in "txid:vout" format; may be repeated',
    )
    p_create_raw.add_argument("--inputs-file", help="JSON array of transaction inputs")
    p_create_raw.add_argument(
        "--output",
        action="append",
        help='output in "address:amount_sats" format; may be repeated',
    )
    p_create_raw.add_argument("--outputs-file", help="JSON array of transaction outputs")
    p_create_raw.add_argument("--locktime", type=int, default=0)
    p_create_raw.add_argument("--tx-version", type=int, default=2, choices=(1, 2))
    p_create_raw.set_defaults(func=cmd_createrawtransaction, parser=p_create_raw)

    # decoderawtransaction
    p_decode_raw = sub.add_parser(
        "decoderawtransaction",
        help="decode a legacy or SegWit raw transaction",
    )
    add_raw_transaction_source(p_decode_raw)
    p_decode_raw.set_defaults(func=cmd_decoderawtransaction, parser=p_decode_raw)

    # fundrawtransaction
    p_fund_raw = sub.add_parser(
        "fundrawtransaction",
        help="select wallet UTXOs and add change to a raw transaction",
    )
    add_wallet_access_arguments(p_fund_raw)
    add_raw_transaction_source(p_fund_raw)
    add_funding_arguments(p_fund_raw)
    p_fund_raw.add_argument("--output-file", help="funded transaction JSON output path")
    p_fund_raw.set_defaults(func=cmd_fundrawtransaction, parser=p_fund_raw)

    # signrawtransactionwithwallet
    p_sign_raw = sub.add_parser(
        "signrawtransactionwithwallet",
        help="sign and locally verify a funded transaction document",
    )
    add_wallet_access_arguments(p_sign_raw)
    p_sign_raw.add_argument("--transaction-file", required=True)
    p_sign_raw.add_argument(
        "--password",
        help="wallet password; hidden prompt is safer",
    )
    p_sign_raw.add_argument("--max-fee-sats", type=int)
    p_sign_raw.add_argument("--output-file", help="signed transaction JSON output path")
    p_sign_raw.set_defaults(func=cmd_signrawtransactionwithwallet, parser=p_sign_raw)

    # sendrawtransaction
    p_send_raw = sub.add_parser(
        "sendrawtransaction",
        help="broadcast a signed transaction through Esplora",
    )
    p_send_raw.add_argument(
        "--datadir",
        help="wallet data directory (overrides BITCOIN_TOOL_DATADIR)",
    )
    add_raw_transaction_source(p_send_raw, include_document=True)
    add_backend_arguments(p_send_raw)
    p_send_raw.add_argument("--max-fee-sats", type=int)
    add_broadcast_confirmation_arguments(p_send_raw)
    p_send_raw.set_defaults(func=cmd_sendrawtransaction, parser=p_send_raw)

    # sendtoaddress
    p_send_to = sub.add_parser(
        "sendtoaddress",
        help="fund, sign, verify, and broadcast a wallet payment",
    )
    add_wallet_access_arguments(p_send_to)
    p_send_to.add_argument(
        "--to-address",
        "--address",
        dest="address",
        required=True,
        help="destination address",
    )
    p_send_to.add_argument("--amount-sats", type=int, required=True)
    p_send_to.add_argument(
        "--password",
        help="wallet password; hidden prompt is safer",
    )
    p_send_to.add_argument(
        "--output-file",
        help="save the signed transaction document here before broadcasting",
    )
    add_funding_arguments(p_send_to)
    add_broadcast_confirmation_arguments(p_send_to)
    p_send_to.add_argument(
        "--dry-run",
        action="store_true",
        help="fund and sign but never broadcast",
    )
    p_send_to.set_defaults(func=cmd_sendtoaddress, parser=p_send_to)

    # sendall
    p_send_all = sub.add_parser(
        "sendall",
        help="spend all eligible wallet UTXOs to one address without change",
    )
    add_wallet_access_arguments(p_send_all)
    p_send_all.add_argument(
        "--to-address",
        "--address",
        dest="address",
        required=True,
        help="destination address",
    )
    p_send_all.add_argument(
        "--password",
        help="wallet password; hidden prompt is safer",
    )
    p_send_all.add_argument(
        "--output-file",
        help="save the signed transaction document here before broadcasting",
    )
    add_funding_arguments(p_send_all, include_utxo=False)
    add_broadcast_confirmation_arguments(p_send_all)
    p_send_all.add_argument(
        "--dry-run",
        action="store_true",
        help="fund and sign but never broadcast",
    )
    p_send_all.set_defaults(func=cmd_sendall, parser=p_send_all)

    # shell
    p_shell = sub.add_parser(
        "shell",
        help="start the interactive shell with command completion",
    )
    p_shell.set_defaults(
        func=cmd_shell,
        parser=p_shell,
    )

    return parser

def run_cli(argv: list[str] | None = None) -> None:    
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        argv = ["shell"]
        
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)

def main() -> None:
    run_cli()

if __name__ == "__main__":
    main()
