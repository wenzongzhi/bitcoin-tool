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

import json
import os
import re
import secrets
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from bip32 import BIP32
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from mnemonic import Mnemonic
from filelock import FileLock, Timeout
from platformdirs import user_data_path

from btc.btc_address_gen import p2wpkh_bech32_address, privkey_to_pubkey


WALLET_FILENAME = "wallets.json"
APP_NAME = "bitcoin-tool"
DATADIR_ENV = "BITCOIN_TOOL_DATADIR"
BTC_RECEIVE_PATH = "m/84'/0'/0'/0"
PBKDF2_ITERATIONS = 200_000
WALLET_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


class WalletError(Exception):
    pass


def default_data_dir(data_dir: str | Path | None = None) -> Path:
    configured_dir = data_dir or os.environ.get(DATADIR_ENV)
    if configured_dir:
        return Path(configured_dir).expanduser().resolve()
    return user_data_path(APP_NAME, appauthor=False)


def default_wallet_file(data_dir: str | Path | None = None) -> Path:
    return default_data_dir(data_dir) / WALLET_FILENAME


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@contextmanager
def _locked_wallet_file(wallet_file: Path):
    try:
        wallet_file.parent.mkdir(parents=True, exist_ok=True)
        lock = FileLock(f"{wallet_file}.lock")
        with lock.acquire(timeout=10):
            yield
    except Timeout as exc:
        raise WalletError(f'wallet file is busy: "{wallet_file}"') from exc
    except OSError as exc:
        raise WalletError(f'cannot lock wallet file "{wallet_file}": {exc}') from exc


def _derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def _load_wallets(wallet_file: Path) -> dict:
    try:
        with wallet_file.open("r", encoding="utf-8") as file:
            wallets = json.load(file)
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        raise WalletError(f'cannot read wallet file "{wallet_file}": {exc}') from exc

    if not isinstance(wallets, dict):
        raise WalletError(f'invalid wallet file "{wallet_file}"')
    return wallets


def _save_wallets(wallets: dict, wallet_file: Path) -> None:
    wallet_file.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=wallet_file.parent,
            prefix=f".{wallet_file.name}.",
            suffix=".tmp",
            delete=False,
        ) as file:
            temporary_path = Path(file.name)
            json.dump(wallets, file, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary_path, wallet_file)
    except OSError as exc:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise WalletError(f'cannot write wallet file "{wallet_file}": {exc}') from exc


def _validate_wallet_name(wallet_name: str) -> None:
    if not WALLET_NAME_PATTERN.fullmatch(wallet_name):
        raise WalletError(
            "wallet name may contain only letters, numbers, underscores, and hyphens"
        )


def _mnemonic_from_entropy(entropy_hex: str | None) -> str:
    if entropy_hex is None:
        entropy = secrets.token_bytes(32)
    else:
        if len(entropy_hex) != 64:
            raise WalletError("entropy must be exactly 256 bits (64 hex characters)")
        try:
            entropy = bytes.fromhex(entropy_hex)
        except ValueError as exc:
            raise WalletError("entropy contains invalid hexadecimal characters") from exc

    return Mnemonic("english").to_mnemonic(entropy)


def create_wallet(
    wallet_name: str,
    password: str | None = None,
    entropy_hex: str | None = None,
    wallet_file: Path | None = None,
) -> dict:
    _validate_wallet_name(wallet_name)
    if password == "":
        raise WalletError("password must not be empty; omit it to create a plaintext wallet")

    path = wallet_file or default_wallet_file()
    mnemonic = _mnemonic_from_entropy(entropy_hex)
    wallet = {
        "version": 1,
        "encrypted": password is not None,
        "derivation_path": BTC_RECEIVE_PATH,
        "next_address_index": 0,
    }

    if password is None:
        wallet["mnemonic"] = mnemonic
    else:
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        key = _derive_key(password, salt, PBKDF2_ITERATIONS)
        ciphertext = AESGCM(key).encrypt(
            nonce,
            mnemonic.encode("utf-8"),
            wallet_name.encode("utf-8"),
        )
        wallet["encryption"] = {
            "cipher": "AES-256-GCM",
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": PBKDF2_ITERATIONS,
            "salt": salt.hex(),
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
        }
    wallet["issued_addresses"] = []

    with _locked_wallet_file(path):
        wallets = _load_wallets(path)
        if wallet_name in wallets:
            raise WalletError(f'wallet "{wallet_name}" already exists')
        wallets[wallet_name] = wallet
        _save_wallets(wallets, path)
    return {
        "wallet_name": wallet_name,
        "mnemonic": mnemonic if password is None else None,
        "encrypted": wallet["encrypted"],
        "wallet_file": str(path),
    }


def _read_mnemonic(wallet_name: str, wallet: dict, password: str | None) -> str:
    if not wallet.get("encrypted"):
        mnemonic = wallet.get("mnemonic")
        if not isinstance(mnemonic, str):
            raise WalletError("wallet does not contain a valid mnemonic")
        return mnemonic

    if password is None:
        raise WalletError("password is required for this encrypted wallet")

    encryption = wallet.get("encryption")
    if not isinstance(encryption, dict):
        raise WalletError("wallet encryption metadata is missing")
    try:
        if encryption.get("cipher") != "AES-256-GCM":
            raise WalletError("unsupported wallet cipher")
        if encryption.get("kdf") != "PBKDF2-HMAC-SHA256":
            raise WalletError("unsupported wallet key derivation function")
        iterations = int(encryption["iterations"])
        if not 100_000 <= iterations <= 10_000_000:
            raise WalletError("wallet PBKDF2 iteration count is invalid")
        salt = bytes.fromhex(encryption["salt"])
        nonce = bytes.fromhex(encryption["nonce"])
        ciphertext = bytes.fromhex(encryption["ciphertext"])
        key = _derive_key(password, salt, iterations)
        plaintext = AESGCM(key).decrypt(
            nonce,
            ciphertext,
            wallet_name.encode("utf-8"),
        )
        return plaintext.decode("utf-8")
    except InvalidTag as exc:
        raise WalletError("incorrect password or corrupted wallet data") from exc
    except (KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
        raise WalletError("invalid wallet encryption metadata") from exc


def get_mnemonic(
    wallet_name: str,
    password: str,
    wallet_file: Path | None = None,
) -> dict:
    _validate_wallet_name(wallet_name)
    if not password:
        raise WalletError("password is required")

    path = wallet_file or default_wallet_file()
    with _locked_wallet_file(path):
        wallets = _load_wallets(path)
        wallet = wallets.get(wallet_name)
        if not isinstance(wallet, dict):
            raise WalletError(f'wallet "{wallet_name}" does not exist')
        if not wallet.get("encrypted"):
            raise WalletError("wallet mnemonic is not encrypted")
        mnemonic = _read_mnemonic(wallet_name, wallet, password)
        _validate_mnemonic(mnemonic)

    return {
        "wallet_name": wallet_name,
        "mnemonic": mnemonic,
    }


def get_new_address(
    wallet_name: str,
    password: str | None = None,
    wallet_file: Path | None = None,
) -> dict:
    _validate_wallet_name(wallet_name)
    path = wallet_file or default_wallet_file()
    with _locked_wallet_file(path):
        wallets = _load_wallets(path)
        wallet = wallets.get(wallet_name)
        if not isinstance(wallet, dict):
            raise WalletError(f'wallet "{wallet_name}" does not exist')

        mnemonic = _read_mnemonic(wallet_name, wallet, password)
        _validate_mnemonic(mnemonic)
        index, base_path = _read_derivation_state(wallet)

        issued_addresses = wallet.setdefault("issued_addresses", [])
        if not isinstance(issued_addresses, list):
            raise WalletError("wallet address book is invalid")
        if any(isinstance(entry, dict) and entry.get("index") == index for entry in issued_addresses):
            raise WalletError("wallet address index is already present in the address book")

        entry = _derive_address_entry(mnemonic, base_path, index, created_at=_utc_now())
        issued_addresses.append(entry)
        wallet["next_address_index"] = index + 1
        _save_wallets(wallets, path)
    return {
        "wallet_name": wallet_name,
        "address": entry["address"],
        "address_type": entry["type"],
        "index": entry["index"],
        "derivation_path": entry["path"],
    }


def _validate_mnemonic(mnemonic: str) -> None:
    if not Mnemonic("english").check(mnemonic):
        raise WalletError("wallet contains an invalid mnemonic")


def _read_derivation_state(wallet: dict) -> tuple[int, str]:
    try:
        index = int(wallet["next_address_index"])
        base_path = wallet["derivation_path"]
    except (KeyError, TypeError, ValueError) as exc:
        raise WalletError("wallet derivation metadata is invalid") from exc
    if base_path != BTC_RECEIVE_PATH or not 0 <= index < 2**31:
        raise WalletError("wallet address index or derivation path is invalid")
    return index, base_path


def _derive_address_entry(
    mnemonic: str,
    base_path: str,
    index: int,
    created_at: str | None,
    label: str = "",
) -> dict:
    derivation_path = f"{base_path}/{index}"
    seed = Mnemonic.to_seed(mnemonic, passphrase="")
    private_key = BIP32.from_seed(seed).get_privkey_from_path(derivation_path)
    public_key = privkey_to_pubkey(private_key, compressed=True)
    return {
        "index": index,
        "path": derivation_path,
        "address": p2wpkh_bech32_address(public_key),
        "type": "P2WPKH",
        "purpose": "receive",
        "label": label,
        "created_at": created_at,
    }


def rebuild_address_book(
    wallet_name: str,
    password: str | None = None,
    wallet_file: Path | None = None,
) -> dict:
    _validate_wallet_name(wallet_name)
    path = wallet_file or default_wallet_file()
    with _locked_wallet_file(path):
        wallets = _load_wallets(path)
        wallet = wallets.get(wallet_name)
        if not isinstance(wallet, dict):
            raise WalletError(f'wallet "{wallet_name}" does not exist')

        mnemonic = _read_mnemonic(wallet_name, wallet, password)
        _validate_mnemonic(mnemonic)
        next_index, base_path = _read_derivation_state(wallet)
        existing_entries = wallet.get("issued_addresses", [])
        if not isinstance(existing_entries, list):
            raise WalletError("wallet address book is invalid")

        existing_by_index = {
            entry["index"]: entry
            for entry in existing_entries
            if isinstance(entry, dict) and isinstance(entry.get("index"), int)
        }
        rebuilt_entries = []
        recovered_at = _utc_now()
        recovered_count = 0
        for index in range(next_index):
            existing = existing_by_index.get(index, {})
            created_at = existing.get("created_at")
            label = existing.get("label", "")
            if not isinstance(created_at, str):
                created_at = None
            if not isinstance(label, str):
                label = ""
            entry = _derive_address_entry(mnemonic, base_path, index, created_at, label)
            if created_at is None:
                entry["recovered_at"] = recovered_at
                recovered_count += 1
            rebuilt_entries.append(entry)

        wallet["issued_addresses"] = rebuilt_entries
        _save_wallets(wallets, path)

    return {
        "wallet_name": wallet_name,
        "address_count": len(rebuilt_entries),
        "recovered_count": recovered_count,
        "wallet_file": str(path),
    }
