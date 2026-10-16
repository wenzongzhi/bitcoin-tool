"""Strict Base58Check and raw scalar import; WIF is never persisted."""

import re

from btc.btc_address_gen import BASE58_ALPHABET, base58check, sha256
from btc.chainparams import NETWORK_MAINNET, get_chain_params
from .constants import CURVE_ORDER
from .errors import SingleKeyWalletError


def validate_private_key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != 32 or not 1 <= int.from_bytes(key, "big") < CURVE_ORDER:
        raise SingleKeyWalletError("invalid secp256k1 private key scalar")
    return key


def parse_private_key_hex(value: str) -> bytes:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
        raise SingleKeyWalletError("private key must be exactly 64 hexadecimal characters")
    return validate_private_key(bytes.fromhex(value))


def decode_base58check(value: str) -> bytes:
    if not isinstance(value, str) or not 1 <= len(value) <= 120:
        raise SingleKeyWalletError("invalid Base58Check encoding")
    number = 0
    for character in value:
        digit = BASE58_ALPHABET.find(character)
        if digit < 0:
            raise SingleKeyWalletError("invalid Base58Check encoding")
        number = number * 58 + digit
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(value) - len(value.lstrip("1"))) + raw
    if len(raw) < 5 or sha256(sha256(raw[:-4]))[:4] != raw[-4:]:
        raise SingleKeyWalletError("invalid Base58Check checksum")
    return raw[:-4]


def _version(network: str) -> bytes:
    try:
        get_chain_params(network)
    except ValueError as exc:
        raise SingleKeyWalletError(str(exc)) from exc
    return b"\x80" if network == NETWORK_MAINNET else b"\xef"


def decode_wif(value: str, network: str) -> tuple[bytes, bool]:
    payload = decode_base58check(value)
    if payload[:1] != _version(network):
        raise SingleKeyWalletError("WIF does not belong to the selected network")
    if len(payload) == 33:
        compressed = False
    elif len(payload) == 34 and payload[-1] == 1:
        compressed = True
    else:
        raise SingleKeyWalletError("invalid WIF payload or compression marker")
    return validate_private_key(payload[1:33]), compressed


def encode_wif(key: bytes, network: str, compressed: bool = True) -> str:
    validate_private_key(key)
    if not isinstance(compressed, bool):
        raise SingleKeyWalletError("WIF compression choice must be boolean")
    return base58check(_version(network), key + (b"\x01" if compressed else b""))
