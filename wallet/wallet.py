import json
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path

from bip32 import BIP32
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from mnemonic import Mnemonic

from btc.btc_address_gen import p2wpkh_bech32_address, privkey_to_pubkey


WALLET_FILENAME = "wallets.json"
BTC_RECEIVE_PATH = "m/84'/0'/0'/0"
PBKDF2_ITERATIONS = 200_000
WALLET_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


class WalletError(Exception):
    pass


def default_wallet_file() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / WALLET_FILENAME
    return Path(__file__).resolve().parent.parent / WALLET_FILENAME


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
    wallets = _load_wallets(path)
    if wallet_name in wallets:
        raise WalletError(f'wallet "{wallet_name}" already exists')

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

    wallets[wallet_name] = wallet
    _save_wallets(wallets, path)
    return {
        "wallet_name": wallet_name,
        "mnemonic": mnemonic,
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


def get_new_address(
    wallet_name: str,
    password: str | None = None,
    wallet_file: Path | None = None,
) -> dict:
    _validate_wallet_name(wallet_name)
    path = wallet_file or default_wallet_file()
    wallets = _load_wallets(path)
    wallet = wallets.get(wallet_name)
    if not isinstance(wallet, dict):
        raise WalletError(f'wallet "{wallet_name}" does not exist')

    mnemonic = _read_mnemonic(wallet_name, wallet, password)
    if not Mnemonic("english").check(mnemonic):
        raise WalletError("wallet contains an invalid mnemonic")

    try:
        index = int(wallet["next_address_index"])
        base_path = wallet["derivation_path"]
    except (KeyError, TypeError, ValueError) as exc:
        raise WalletError("wallet derivation metadata is invalid") from exc
    if base_path != BTC_RECEIVE_PATH or not 0 <= index < 2**31:
        raise WalletError("wallet address index or derivation path is invalid")

    derivation_path = f"{base_path}/{index}"
    seed = Mnemonic.to_seed(mnemonic, passphrase="")
    private_key = BIP32.from_seed(seed).get_privkey_from_path(derivation_path)
    public_key = privkey_to_pubkey(private_key, compressed=True)
    address = p2wpkh_bech32_address(public_key)

    wallet["next_address_index"] = index + 1
    _save_wallets(wallets, path)
    return {
        "wallet_name": wallet_name,
        "address": address,
        "address_type": "P2WPKH",
        "derivation_path": derivation_path,
    }
