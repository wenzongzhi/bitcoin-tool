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

from btc.btc_address_gen import p2wpkh_bech32_address, p2wpkh_script_pubkey


WALLET_FILENAME = "wallets.json"
APP_NAME = "bitcoin-tool"
DATADIR_ENV = "BITCOIN_TOOL_DATADIR"
BTC_ACCOUNT_PATH = "m/84'/0'/0'"
BTC_RECEIVE_BRANCH = 0
BTC_CHANGE_BRANCH = 1
ADDRESS_TYPE_P2WPKH = "P2WPKH"
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


def mnemonic_from_entropy_hex(entropy_hex: str) -> str:
    try:
        entropy = bytes.fromhex(entropy_hex)
    except ValueError as exc:
        raise WalletError("entropy contains invalid hexadecimal characters") from exc
    try:
        return Mnemonic("english").to_mnemonic(entropy)
    except ValueError as exc:
        raise WalletError("entropy must be 128, 160, 192, 224, or 256 bits") from exc


def entropy_hex_from_mnemonic(mnemonic: str) -> str:
    normalized_mnemonic = normalize_mnemonic(mnemonic)
    try:
        return Mnemonic("english").to_entropy(normalized_mnemonic).hex()
    except ValueError as exc:
        raise WalletError("mnemonic is invalid") from exc


def normalize_mnemonic(mnemonic: str) -> str:
    normalized_mnemonic = " ".join(mnemonic.strip().split())
    if not Mnemonic("english").check(normalized_mnemonic):
        raise WalletError("mnemonic is invalid")
    return normalized_mnemonic


def _mnemonic_from_entropy(entropy_hex: str | None) -> str:
    if entropy_hex is None:
        entropy = secrets.token_bytes(32)
        return Mnemonic("english").to_mnemonic(entropy)

    if len(entropy_hex) != 64:
        raise WalletError("entropy must be exactly 256 bits (64 hex characters)")
    return mnemonic_from_entropy_hex(entropy_hex)


def _derive_account_metadata(mnemonic: str) -> dict:
    seed = Mnemonic.to_seed(mnemonic, passphrase="")
    bip32 = BIP32.from_seed(seed)
    return {
        "account_xpub": bip32.get_xpub_from_path(BTC_ACCOUNT_PATH),
        "master_fingerprint": bip32.get_fingerprint().hex(),
    }


def create_wallet(
    wallet_name: str,
    password: str | None = None,
    entropy_hex: str | None = None,
    wallet_file: Path | None = None,
    *,
    mnemonic: str | None = None,
) -> dict:
    _validate_wallet_name(wallet_name)
    if password == "":
        raise WalletError("password must not be empty; omit it to create a plaintext wallet")
    if entropy_hex is not None and mnemonic is not None:
        raise WalletError("entropy and mnemonic are mutually exclusive")

    path = wallet_file or default_wallet_file()
    if mnemonic is not None:
        mnemonic = normalize_mnemonic(mnemonic)
    else:
        mnemonic = _mnemonic_from_entropy(entropy_hex)
    account_metadata = _derive_account_metadata(mnemonic)
    wallet = {
        "version": 2,
        "encrypted": password is not None,
        "address_type": ADDRESS_TYPE_P2WPKH,
        "account_derivation_path": BTC_ACCOUNT_PATH,
        "account_xpub": account_metadata["account_xpub"],
        "master_fingerprint": account_metadata["master_fingerprint"],
        "receive_branch": BTC_RECEIVE_BRANCH,
        "change_branch": BTC_CHANGE_BRANCH,
        "next_receive_index": 0,
        "next_change_index": 0,
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
        "account_xpub": account_metadata["account_xpub"],
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
    password: str | None = None,
    wallet_file: Path | None = None,
) -> dict:
    _validate_wallet_name(wallet_name)

    path = wallet_file or default_wallet_file()
    with _locked_wallet_file(path):
        wallets = _load_wallets(path)
        wallet = wallets.get(wallet_name)

        if not isinstance(wallet, dict):
            raise WalletError(f'wallet "{wallet_name}" does not exist in "{path}"')
        mnemonic = _read_mnemonic(wallet_name, wallet, password)
        _validate_mnemonic(mnemonic)

    return {
        "wallet_name": wallet_name,
        "mnemonic": mnemonic,
    }


def get_new_address(
    wallet_name: str,
    wallet_file: Path | None = None,
    change: bool = False,
) -> dict:
    _validate_wallet_name(wallet_name)
    branch = BTC_CHANGE_BRANCH if change else BTC_RECEIVE_BRANCH
    purpose = _branch_purpose(branch)
    path = wallet_file or default_wallet_file()
    with _locked_wallet_file(path):
        wallets = _load_wallets(path)
        wallet = wallets.get(wallet_name)
        if not isinstance(wallet, dict):
            raise WalletError(f'wallet "{wallet_name}" does not exist in "{path}"')

        account_xpub, account_path, index = _read_public_derivation_state(wallet, branch)

        issued_addresses = wallet.get("issued_addresses")
        if not isinstance(issued_addresses, list):
            raise WalletError("wallet address book is invalid")
        if any(
            isinstance(entry, dict)
            and _entry_branch(entry) == branch
            and entry.get("index") == index
            for entry in issued_addresses
        ):
            raise WalletError("wallet address index is already present in the address book")

        entry = _derive_address_entry_from_xpub(
            account_xpub,
            account_path,
            branch,
            index,
            created_at=_utc_now(),
            label="",
        )
        issued_addresses.append(entry)
        wallet[_next_index_key(branch)] = index + 1
        _save_wallets(wallets, path)
    return {
        "wallet_name": wallet_name,
        "address": entry["address"],
        "address_type": entry["type"],
        "purpose": purpose,
        "branch": branch,
        "index": entry["index"],
        "relative_derivation_path": entry["relative_path"],
        "derivation_path": entry["path"],
    }


def _validate_mnemonic(mnemonic: str) -> None:
    if not Mnemonic("english").check(mnemonic):
        raise WalletError("wallet contains an invalid mnemonic")


def _branch_purpose(branch: int) -> str:
    if branch == BTC_RECEIVE_BRANCH:
        return "receive"
    if branch == BTC_CHANGE_BRANCH:
        return "change"
    raise WalletError("branch must be 0 receiving or 1 change")


def _next_index_key(branch: int) -> str:
    _branch_purpose(branch)
    return "next_receive_index" if branch == BTC_RECEIVE_BRANCH else "next_change_index"


def _entry_branch(entry: dict) -> int:
    branch = entry.get("branch")
    if isinstance(branch, int):
        return branch
    raise WalletError("wallet address book is invalid")


def _read_public_derivation_state(wallet: dict, branch: int) -> tuple[str, str, int]:
    key = _next_index_key(branch)
    try:
        account_xpub = wallet["account_xpub"]
        account_path = wallet["account_derivation_path"]
        address_type = wallet["address_type"]
        receive_branch = int(wallet["receive_branch"])
        change_branch = int(wallet["change_branch"])
        index = int(wallet[key])
    except (KeyError, TypeError, ValueError) as exc:
        raise WalletError("wallet xpub metadata is invalid") from exc
    if not isinstance(account_xpub, str) or not account_xpub:
        raise WalletError("wallet xpub metadata is invalid")
    if address_type != ADDRESS_TYPE_P2WPKH:
        raise WalletError("only P2WPKH wallet address derivation is currently supported")
    if (
        account_path != BTC_ACCOUNT_PATH
        or receive_branch != BTC_RECEIVE_BRANCH
        or change_branch != BTC_CHANGE_BRANCH
        or not 0 <= index < 2**31
    ):
        raise WalletError("wallet address index or derivation path is invalid")
    return account_xpub, account_path, index


def derive_p2wpkh_from_account_xpub(account_xpub: str, branch: int, index: int) -> str:
    if branch not in (BTC_RECEIVE_BRANCH, BTC_CHANGE_BRANCH):
        raise WalletError("branch must be 0 receiving or 1 change")
    if not 0 <= index < 2**31:
        raise WalletError("index must be non-hardened and in range 0..2147483647")
    if not isinstance(account_xpub, str) or not account_xpub:
        raise WalletError("account xpub is required")

    try:
        public_key = BIP32.from_xpub(account_xpub).get_pubkey_from_path(
            f"m/{branch}/{index}"
        )
    except Exception as exc:
        raise WalletError("cannot derive public key from account xpub") from exc
    return p2wpkh_bech32_address(public_key)


def derive_p2wpkh_public_key_from_account_xpub(
    account_xpub: str,
    branch: int,
    index: int,
) -> bytes:
    if branch not in (BTC_RECEIVE_BRANCH, BTC_CHANGE_BRANCH):
        raise WalletError("branch must be 0 receiving or 1 change")
    if not 0 <= index < 2**31:
        raise WalletError("index must be non-hardened and in range 0..2147483647")
    if not isinstance(account_xpub, str) or not account_xpub:
        raise WalletError("account xpub is required")

    try:
        return BIP32.from_xpub(account_xpub).get_pubkey_from_path(
            f"m/{branch}/{index}"
        )
    except Exception as exc:
        raise WalletError("cannot derive public key from account xpub") from exc


def _derive_address_entry_from_xpub(
    account_xpub: str,
    account_path: str,
    branch: int,
    index: int,
    created_at: str | None,
    label: str = "",
) -> dict:
    relative_path = f"m/{branch}/{index}"
    derivation_path = f"{account_path}/{branch}/{index}"
    public_key = derive_p2wpkh_public_key_from_account_xpub(
        account_xpub,
        branch,
        index,
    )
    return {
        "index": index,
        "branch": branch,
        "relative_path": relative_path,
        "path": derivation_path,
        "address": p2wpkh_bech32_address(public_key),
        "script_pubkey": p2wpkh_script_pubkey(public_key),
        "type": ADDRESS_TYPE_P2WPKH,
        "purpose": _branch_purpose(branch),
        "used": False,
        "label": label,
        "created_at": created_at,
    }


def get_wallet_address_book(
    wallet_name: str,
    wallet_file: Path | None = None,
) -> dict:
    _validate_wallet_name(wallet_name)
    path = wallet_file or default_wallet_file()
    with _locked_wallet_file(path):
        wallets = _load_wallets(path)
        wallet = wallets.get(wallet_name)
        if not isinstance(wallet, dict):
            raise WalletError(f'wallet "{wallet_name}" does not exist in "{path}"')

        _read_public_derivation_state(wallet, BTC_RECEIVE_BRANCH)
        issued_addresses = wallet.get("issued_addresses", [])
        if not isinstance(issued_addresses, list):
            raise WalletError("wallet address book is invalid")

        normalized_entries = []
        for entry in issued_addresses:
            if not isinstance(entry, dict):
                raise WalletError("wallet address book is invalid")
            try:
                branch = _entry_branch(entry)
                index = int(entry["index"])
                address = entry["address"]
                relative_path = entry["relative_path"]
                path_value = entry["path"]
                script_pubkey = entry["script_pubkey"]
                address_type = entry["type"]
                purpose = entry["purpose"]
                used = entry["used"]
                label = entry["label"]
                created_at = entry["created_at"]
            except (KeyError, TypeError, ValueError) as exc:
                raise WalletError("wallet address book is invalid") from exc
            if branch not in (BTC_RECEIVE_BRANCH, BTC_CHANGE_BRANCH):
                raise WalletError("wallet address book is invalid")
            if (
                not isinstance(address, str)
                or not isinstance(relative_path, str)
                or not isinstance(path_value, str)
                or not isinstance(script_pubkey, str)
                or address_type != ADDRESS_TYPE_P2WPKH
                or purpose != _branch_purpose(branch)
                or not isinstance(used, bool)
                or not isinstance(label, str)
            ):
                raise WalletError("wallet address book is invalid")
            if created_at is not None and not isinstance(created_at, str):
                raise WalletError("wallet address book is invalid")
            if not 0 <= index < 2**31:
                raise WalletError("wallet address book is invalid")
            normalized_entries.append(dict(entry))

    return {
        "wallet_name": wallet_name,
        "wallet_file": str(path),
        "address_count": len(normalized_entries),
        "addresses": normalized_entries,
    }


def mark_wallet_addresses_used(
    wallet_name: str,
    used_addresses: set[str],
    wallet_file: Path | None = None,
) -> int:
    _validate_wallet_name(wallet_name)
    path = wallet_file or default_wallet_file()
    changed_count = 0
    with _locked_wallet_file(path):
        wallets = _load_wallets(path)
        wallet = wallets.get(wallet_name)
        if not isinstance(wallet, dict):
            raise WalletError(f'wallet "{wallet_name}" does not exist in "{path}"')
        issued_addresses = wallet.get("issued_addresses", [])
        if not isinstance(issued_addresses, list):
            raise WalletError("wallet address book is invalid")

        for entry in issued_addresses:
            if not isinstance(entry, dict):
                raise WalletError("wallet address book is invalid")
            address = entry.get("address")
            if isinstance(address, str) and address in used_addresses and not entry.get("used"):
                entry["used"] = True
                changed_count += 1

        if changed_count:
            _save_wallets(wallets, path)
    return changed_count


def _descriptor_like(account_xpub: str, master_fingerprint: str) -> str:
    account_suffix = BTC_ACCOUNT_PATH.removeprefix("m/")
    return f"wpkh([{master_fingerprint}/{account_suffix}]{account_xpub}/0/*)"


def export_account_xpub(
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
            raise WalletError(f'wallet "{wallet_name}" does not exist in "{path}"')

        if wallet.get("encrypted"):
            if not password:
                raise WalletError("password is required to export account xpub")
            mnemonic = _read_mnemonic(wallet_name, wallet, password)
            _validate_mnemonic(mnemonic)

        account_xpub, account_path, _ = _read_public_derivation_state(
            wallet,
            BTC_RECEIVE_BRANCH,
        )
        master_fingerprint = wallet.get("master_fingerprint")
        if not isinstance(master_fingerprint, str) or not re.fullmatch(
            r"[0-9a-fA-F]{8}",
            master_fingerprint,
        ):
            raise WalletError("wallet master fingerprint metadata is invalid")

    return {
        "wallet_name": wallet_name,
        "address_type": ADDRESS_TYPE_P2WPKH,
        "account_derivation_path": account_path,
        "account_xpub": account_xpub,
        "descriptor_like": _descriptor_like(account_xpub, master_fingerprint.lower()),
    }


def rebuild_address_book(
    wallet_name: str,
    wallet_file: Path | None = None,
) -> dict:
    _validate_wallet_name(wallet_name)
    path = wallet_file or default_wallet_file()
    with _locked_wallet_file(path):
        wallets = _load_wallets(path)
        wallet = wallets.get(wallet_name)
        if not isinstance(wallet, dict):
            raise WalletError(f'wallet "{wallet_name}" does not exist')

        account_xpub, account_path, next_receive_index = _read_public_derivation_state(
            wallet,
            BTC_RECEIVE_BRANCH,
        )
        _, _, next_change_index = _read_public_derivation_state(
            wallet,
            BTC_CHANGE_BRANCH,
        )
        existing_entries = wallet.get("issued_addresses", [])
        if not isinstance(existing_entries, list):
            raise WalletError("wallet address book is invalid")

        existing_by_index = {
            (_entry_branch(entry), entry["index"]): entry
            for entry in existing_entries
            if isinstance(entry, dict) and isinstance(entry.get("index"), int)
        }
        rebuilt_entries = []
        recovered_at = _utc_now()
        recovered_count = 0
        for branch, next_index in (
            (BTC_RECEIVE_BRANCH, next_receive_index),
            (BTC_CHANGE_BRANCH, next_change_index),
        ):
            for index in range(next_index):
                existing = existing_by_index.get((branch, index), {})
                created_at = existing.get("created_at")
                label = existing.get("label", "")
                used = existing.get("used", False)
                if not isinstance(created_at, str):
                    created_at = None
                if not isinstance(label, str):
                    label = ""
                if not isinstance(used, bool):
                    used = False
                entry = _derive_address_entry_from_xpub(
                    account_xpub,
                    account_path,
                    branch,
                    index,
                    created_at,
                    label,
                )
                entry["used"] = used
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
