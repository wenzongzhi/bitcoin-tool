"""Authoritative fixed-key wallet records and authenticated secret storage."""

from copy import deepcopy
import json
from pathlib import Path
import re
import secrets
import uuid

from coincurve import PrivateKey, PublicKey
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from btc.btc_address_gen import (
    pubkey_to_p2pkh, p2pkh_script_pubkey, p2wpkh_bech32_address,
    p2wpkh_script_pubkey, p2sh_p2wpkh_address, p2sh_p2wpkh_script_pubkey,
    p2tr_address, p2tr_script_pubkey, p2tr_output_key,
)
from btc.chainparams import get_chain_params
from .constants import (
    SINGLE_KEY_WALLET_VERSION, SYNC_ADDRESS_TYPES, SPEND_ADDRESS_TYPES,
    ADDRESS_TYPE_P2PKH_COMPRESSED, ADDRESS_TYPE_P2PKH_UNCOMPRESSED,
    ADDRESS_TYPE_P2WPKH,
)
from .errors import SingleKeyWalletError
from .storage import locked_file, read_json, write_json, utc_now
from .wif import decode_wif, parse_private_key_hex, validate_private_key

PBKDF2_ITERATIONS = 200_000


def validate_wallet_name(name: str) -> None:
    if not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", name) is None:
        raise SingleKeyWalletError("wallet name must contain 1..128 letters, digits, underscores or hyphens")


def public_metadata(compressed: bytes, network: str) -> dict:
    try:
        get_chain_params(network)
        public = PublicKey(compressed)
        if len(compressed) != 33 or public.format() != compressed:
            raise ValueError
        uncompressed = public.format(compressed=False)
        pairs = (
            (pubkey_to_p2pkh(compressed, network), p2pkh_script_pubkey(compressed)),
            (pubkey_to_p2pkh(uncompressed, network), p2pkh_script_pubkey(uncompressed)),
            (p2wpkh_bech32_address(compressed, network), p2wpkh_script_pubkey(compressed)),
            (p2sh_p2wpkh_address(compressed, network), p2sh_p2wpkh_script_pubkey(compressed)),
            (p2tr_address(compressed, network), p2tr_script_pubkey(compressed)),
        )
    except (ValueError, TypeError) as exc:
        raise SingleKeyWalletError("invalid single-key public metadata or network") from exc
    return {
        "public_keys": {
            "compressed": compressed.hex(), "uncompressed": uncompressed.hex(),
            "xonly": compressed[1:].hex(), "taproot_output_key": p2tr_output_key(compressed).hex(),
        },
        "addresses": {
            kind: {
                "address": address, "script_pubkey": script,
                "sync_supported": True,
                "receive_supported": kind in SPEND_ADDRESS_TYPES,
                "spend_supported": kind in SPEND_ADDRESS_TYPES,
            }
            for kind, (address, script) in zip(SYNC_ADDRESS_TYPES, pairs)
        },
    }


def _aad(name: str, record: dict) -> bytes:
    metadata = {key: value for key, value in record.items() if key not in ("secret", "encrypted")}
    return json.dumps({"name": name, **metadata}, sort_keys=True, separators=(",", ":")).encode()


def _derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    if not isinstance(password, str):
        raise SingleKeyWalletError("wallet password is required")
    return PBKDF2HMAC(hashes.SHA256(), 32, salt, iterations).derive(password.encode("utf-8"))


def _store_secret(name: str, record: dict, key: bytes, password: str | None) -> None:
    record["encrypted"] = password is not None
    if password is None:
        record["secret"] = {"format": "raw-private-key", "private_key_hex": key.hex()}
        return
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    ciphertext = AESGCM(_derive_key(password, salt, PBKDF2_ITERATIONS)).encrypt(nonce, key, _aad(name, record))
    record["secret"] = {
        "format": "raw-private-key",
        "encryption": {
            "cipher": "AES-256-GCM", "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": PBKDF2_ITERATIONS, "salt": salt.hex(),
            "nonce": nonce.hex(), "ciphertext": ciphertext.hex(),
        },
    }


def validate_record(record: dict, network: str) -> None:
    try:
        if (record["version"] != SINGLE_KEY_WALLET_VERSION or record["network"] != network
            or not isinstance(record["encrypted"], bool)
            or re.fullmatch(r"[a-f0-9]{32}", record["wallet_id"]) is None):
            raise ValueError
        expected = public_metadata(bytes.fromhex(record["public_keys"]["compressed"]), network)
        if record["public_keys"] != expected["public_keys"] or record["addresses"] != expected["addresses"]:
            raise ValueError
        origin = record["key_origin"]
        if origin["type"] not in ("generated", "hex", "wif"):
            raise ValueError
        if origin["type"] == "wif":
            if not isinstance(origin["wif_compressed"], bool):
                raise ValueError
        elif origin["wif_compressed"] is not None:
            raise ValueError
        preference = record["preferences"]
        if (preference["default_receive_address_type"] not in SPEND_ADDRESS_TYPES
            or preference["default_legacy_pubkey_format"] not in ("compressed", "uncompressed")):
            raise ValueError
        secret = record["secret"]
        if secret["format"] != "raw-private-key":
            raise ValueError
        expected_fields = {"format", "encryption" if record["encrypted"] else "private_key_hex"}
        if set(secret) != expected_fields:
            raise ValueError
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise SingleKeyWalletError("invalid single-key wallet record") from exc


def load_wallet(name: str, wallet_file: Path, network: str) -> dict:
    validate_wallet_name(name)
    with locked_file(wallet_file):
        record = read_json(wallet_file, {}).get(name)
    if not isinstance(record, dict):
        raise SingleKeyWalletError("single-key wallet does not exist")
    validate_record(record, network)
    return record


def unlock_private_key(name: str, record: dict, password: str | None) -> bytes:
    try:
        if not record["encrypted"]:
            key = parse_private_key_hex(record["secret"]["private_key_hex"])
        else:
            encryption = record["secret"]["encryption"]
            iterations = encryption["iterations"]
            salt, nonce, ciphertext = (bytes.fromhex(encryption[field]) for field in ("salt", "nonce", "ciphertext"))
            if (encryption["cipher"] != "AES-256-GCM" or encryption["kdf"] != "PBKDF2-HMAC-SHA256"
                or isinstance(iterations, bool) or not isinstance(iterations, int)
                or not 100_000 <= iterations <= 1_000_000
                or len(salt) != 16 or len(nonce) != 12 or len(ciphertext) != 48):
                raise ValueError
            key = AESGCM(_derive_key(password, salt, iterations)).decrypt(nonce, ciphertext, _aad(name, record))
        validate_private_key(key)
        if PrivateKey(key).public_key.format().hex() != record["public_keys"]["compressed"]:
            raise ValueError
        return key
    except (InvalidTag, KeyError, TypeError, ValueError) as exc:
        raise SingleKeyWalletError("wrong password or corrupted single-key wallet secret") from exc


def public_record(name: str, record: dict) -> dict:
    return {"wallet_name": name, **deepcopy({k: v for k, v in record.items() if k != "secret"})}


def create_wallet(name: str, wallet_file: Path, network: str, password=None, *, private_key_hex=None, wif=None) -> dict:
    validate_wallet_name(name)
    if private_key_hex is not None and wif is not None:
        raise SingleKeyWalletError("HEX and WIF inputs are mutually exclusive")
    marker = None
    if private_key_hex is not None:
        key, origin = parse_private_key_hex(private_key_hex), "hex"
    elif wif is not None:
        key, marker = decode_wif(wif, network)
        origin = "wif"
    else:
        key, origin = PrivateKey().secret, "generated"
    record = {
        "version": SINGLE_KEY_WALLET_VERSION, "network": network,
        "wallet_id": uuid.uuid4().hex, "created_at": utc_now(),
        "key_origin": {"type": origin, "wif_compressed": marker},
        "preferences": {
            "default_legacy_pubkey_format": "uncompressed" if marker is False else "compressed",
            "default_receive_address_type": ADDRESS_TYPE_P2PKH_UNCOMPRESSED if marker is False else ADDRESS_TYPE_P2WPKH,
        },
        **public_metadata(PrivateKey(key).public_key.format(), network),
    }
    _store_secret(name, record, key, password)
    del key
    with locked_file(wallet_file):
        wallets = read_json(wallet_file, {})
        for existing in wallets.values():
            validate_record(existing, network)
        if name in wallets:
            raise SingleKeyWalletError("single-key wallet name already exists")
        wallets[name] = record
        write_json(wallet_file, wallets)
    return public_record(name, record)


def change_password(name: str, wallet_file: Path, network: str, password, new_password) -> dict:
    with locked_file(wallet_file):
        wallets = read_json(wallet_file, {})
        record = wallets.get(name)
        validate_record(record, network)
        key = unlock_private_key(name, record, password)
        _store_secret(name, record, key, new_password)
        del key
        write_json(wallet_file, wallets)
    return public_record(name, record)
