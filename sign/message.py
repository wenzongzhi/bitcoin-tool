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

import base64
import hashlib
import struct

from bech32 import decode as decode_segwit_address
from coincurve import PrivateKey, PublicKey
from coincurve.ecdsa import cdata_to_der, deserialize_recoverable, recoverable_convert
from ecdsa import BadSignatureError, MalformedPointError, SECP256k1, SigningKey, VerifyingKey
from ecdsa.der import UnexpectedDER
from ecdsa.util import sigdecode_der, sigencode_der_canonize

from btc.btc_address_gen import (
    hash160,
    is_valid_public_key,
    p2wpkh_bech32_address,
    privkey_to_pubkey,
    pubkey_to_p2pkh,
)
from btc.private_key_gen import SECP256K1_N, is_valid_privkey


class MessageSignatureError(Exception):
    pass


BITCOIN_MESSAGE_PREFIX = b"Bitcoin Signed Message:\n"
BIP322_TAG = b"BIP0322-signed-message"
SIGHASH_ALL = 1


def message_digest(message: str) -> bytes:
    return hashlib.sha256(message.encode("utf-8")).digest()


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _double_sha256(data: bytes) -> bytes:
    return _sha256(_sha256(data))


def _encode_compact_size(value: int) -> bytes:
    if value < 0:
        raise ValueError("compact size cannot be negative")
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + struct.pack("<Q", value)
    raise ValueError("compact size is too large")


def _decode_compact_size(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("truncated compact size")
    prefix = data[offset]
    offset += 1
    if prefix < 0xFD:
        return prefix, offset

    byte_count = {0xFD: 2, 0xFE: 4, 0xFF: 8}[prefix]
    end = offset + byte_count
    if end > len(data):
        raise ValueError("truncated compact size")
    value = int.from_bytes(data[offset:end], "little")
    minimum = {0xFD: 0xFD, 0xFE: 0x10000, 0xFF: 0x100000000}[prefix]
    if value < minimum:
        raise ValueError("non-minimal compact size")
    return value, end


def _serialize_vector(items: list[bytes]) -> bytes:
    return _encode_compact_size(len(items)) + b"".join(
        _encode_compact_size(len(item)) + item for item in items
    )


def _deserialize_vector(data: bytes) -> list[bytes]:
    count, offset = _decode_compact_size(data, 0)
    if count > 100:
        raise ValueError("witness stack is too large")
    items = []
    for _ in range(count):
        length, offset = _decode_compact_size(data, offset)
        end = offset + length
        if end > len(data):
            raise ValueError("truncated witness item")
        items.append(data[offset:end])
        offset = end
    if offset != len(data):
        raise ValueError("trailing witness data")
    return items


def _private_key_from_hex(private_key_hex: str) -> bytes:
    try:
        private_key = bytes.fromhex(private_key_hex)
    except ValueError as exc:
        raise MessageSignatureError("invalid hex private key") from exc

    if not is_valid_privkey(private_key):
        raise MessageSignatureError(
            "invalid private key: must be 32 bytes and 1 <= key < secp256k1_n"
        )
    return private_key


def _public_key_from_hex(public_key_hex: str) -> bytes:
    try:
        public_key = bytes.fromhex(public_key_hex)
    except ValueError as exc:
        raise MessageSignatureError("invalid hex public key") from exc

    if not is_valid_public_key(public_key):
        raise MessageSignatureError(
            "invalid public key: expected a compressed (33-byte) or "
            "uncompressed (65-byte) secp256k1 public key"
        )
    return public_key


def _verifying_key_from_public_key(public_key: bytes) -> VerifyingKey:
    try:
        return VerifyingKey.from_string(
            public_key,
            curve=SECP256k1,
            validate_point=True,
            valid_encodings={"compressed", "uncompressed"},
        )
    except (MalformedPointError, ValueError) as exc:
        raise MessageSignatureError("invalid secp256k1 public key") from exc


def bitcoin_signed_message_hash(message: str) -> bytes:
    message_bytes = message.encode("utf-8")
    payload = (
        _encode_compact_size(len(BITCOIN_MESSAGE_PREFIX))
        + BITCOIN_MESSAGE_PREFIX
        + _encode_compact_size(len(message_bytes))
        + message_bytes
    )
    return _double_sha256(payload)


def _recoverable_signature_to_der(signature: bytes) -> bytes:
    recoverable = deserialize_recoverable(signature)
    return cdata_to_der(recoverable_convert(recoverable))


def _legacy_sign(private_key: bytes, message: str) -> dict:
    digest = bitcoin_signed_message_hash(message)
    recoverable = PrivateKey(private_key).sign_recoverable(digest, hasher=None)
    recovery_id = recoverable[64]
    compact = bytes([27 + recovery_id + 4]) + recoverable[:64]
    return {
        "address": pubkey_to_p2pkh(privkey_to_pubkey(private_key, compressed=True)),
        "message_hash": digest.hex(),
        "signature_der": _recoverable_signature_to_der(recoverable).hex(),
        "signature_base64": base64.b64encode(compact).decode("ascii"),
    }


def verify_legacy_message(address: str, message: str, signature_base64: str) -> bool:
    try:
        compact = base64.b64decode(signature_base64, validate=True)
        if len(compact) != 65 or not 27 <= compact[0] <= 34:
            return False
        header = compact[0] - 27
        compressed = bool(header & 4)
        recovery_id = header & 3
        recoverable = compact[1:] + bytes([recovery_id])
        public_key = PublicKey.from_signature_and_message(
            recoverable,
            bitcoin_signed_message_hash(message),
            hasher=None,
        ).format(compressed=compressed)
        return pubkey_to_p2pkh(public_key) == address
    except (ValueError, TypeError):
        return False


def _tagged_hash(tag: bytes, data: bytes) -> bytes:
    tag_hash = _sha256(tag)
    return _sha256(tag_hash + tag_hash + data)


def _p2wpkh_program_from_address(address: str) -> bytes:
    witness_version, witness_program = decode_segwit_address("bc", address)
    if witness_version != 0 or witness_program is None or len(witness_program) != 20:
        raise MessageSignatureError("invalid mainnet P2WPKH address")
    return bytes(witness_program)


def _bip322_to_spend_tx(message: str, script_pubkey: bytes) -> bytes:
    message_hash = _tagged_hash(BIP322_TAG, message.encode("utf-8"))
    script_sig = b"\x00\x20" + message_hash
    return (
        struct.pack("<I", 0)
        + b"\x01"
        + b"\x00" * 32
        + struct.pack("<I", 0xFFFFFFFF)
        + _encode_compact_size(len(script_sig))
        + script_sig
        + struct.pack("<I", 0)
        + b"\x01"
        + struct.pack("<Q", 0)
        + _encode_compact_size(len(script_pubkey))
        + script_pubkey
        + struct.pack("<I", 0)
    )


def _bip322_p2wpkh_sighash(message: str, public_key_hash: bytes) -> bytes:
    script_pubkey = b"\x00\x14" + public_key_hash
    to_spend_txid = _double_sha256(_bip322_to_spend_tx(message, script_pubkey))
    outpoint = to_spend_txid + struct.pack("<I", 0)
    sequence = struct.pack("<I", 0)
    output = struct.pack("<Q", 0) + b"\x01\x6a"
    script_code = b"\x76\xa9\x14" + public_key_hash + b"\x88\xac"
    preimage = (
        struct.pack("<I", 0)
        + _double_sha256(outpoint)
        + _double_sha256(sequence)
        + outpoint
        + _encode_compact_size(len(script_code))
        + script_code
        + struct.pack("<Q", 0)
        + sequence
        + _double_sha256(output)
        + struct.pack("<I", 0)
        + struct.pack("<I", SIGHASH_ALL)
    )
    return _double_sha256(preimage)


def _bip322_sign(private_key: bytes, message: str) -> dict:
    public_key = privkey_to_pubkey(private_key, compressed=True)
    public_key_hash = hash160(public_key)
    digest = _bip322_p2wpkh_sighash(message, public_key_hash)
    signature_der = PrivateKey(private_key).sign(digest, hasher=None)
    witness = _serialize_vector([signature_der + bytes([SIGHASH_ALL]), public_key])
    return {
        "address": p2wpkh_bech32_address(public_key),
        "message_hash": _tagged_hash(BIP322_TAG, message.encode("utf-8")).hex(),
        "signature_der": signature_der.hex(),
        "signature_base64": "smp" + base64.b64encode(witness).decode("ascii"),
    }


def _is_strict_low_s_der(signature_der: bytes) -> bool:
    try:
        r, s = sigdecode_der(signature_der, SECP256K1_N)
        return (
            1 <= r < SECP256K1_N
            and 1 <= s <= SECP256K1_N // 2
            and sigencode_der_canonize(r, s, SECP256K1_N) == signature_der
        )
    except (UnexpectedDER, ValueError):
        return False


def verify_p2wpkh_message(address: str, message: str, signature_base64: str) -> bool:
    try:
        public_key_hash = _p2wpkh_program_from_address(address)
        encoded_witness = (
            signature_base64[3:]
            if signature_base64.startswith("smp")
            else signature_base64
        )
        witness = _deserialize_vector(
            base64.b64decode(encoded_witness, validate=True)
        )
        if len(witness) != 2:
            return False
        signature_with_type, public_key = witness
        if (
            len(signature_with_type) < 2
            or signature_with_type[-1] != SIGHASH_ALL
            or len(public_key) != 33
            or hash160(public_key) != public_key_hash
            or p2wpkh_bech32_address(public_key).lower() != address.lower()
        ):
            return False
        signature_der = signature_with_type[:-1]
        if not _is_strict_low_s_der(signature_der):
            return False
        digest = _bip322_p2wpkh_sighash(message, public_key_hash)
        return PublicKey(public_key).verify(signature_der, digest, hasher=None)
    except (MessageSignatureError, ValueError, TypeError):
        return False


def bitcoin_sign_message(private_key_hex: str, message: str) -> dict:
    private_key = _private_key_from_hex(private_key_hex)
    public_key = privkey_to_pubkey(private_key, compressed=True)
    return {
        "message": message,
        "public_key_compressed": public_key.hex(),
        "legacy": _legacy_sign(private_key, message),
        "p2wpkh": _bip322_sign(private_key, message),
    }


def ecdsa_sign_message(private_key_hex: str, message: str) -> dict:
    private_key = _private_key_from_hex(private_key_hex)
    signing_key = SigningKey.from_string(private_key, curve=SECP256k1)
    signature = signing_key.sign_digest_deterministic(
        message_digest(message),
        hashfunc=hashlib.sha256,
        sigencode=sigencode_der_canonize,
    )
    public_key_compressed = privkey_to_pubkey(private_key, compressed=True)
    public_key_uncompressed = privkey_to_pubkey(private_key, compressed=False)
    return {
        "message": message,
        "message_hash": message_digest(message).hex(),
        "signature": signature.hex(),
        "signature_format": "DER",
        "public_key_compressed": public_key_compressed.hex(),
        "public_key_uncompressed": public_key_uncompressed.hex(),
    }


def ecdsa_verify_message(public_key_hex: str, message: str, signature_hex: str) -> bool:
    public_key = _public_key_from_hex(public_key_hex)
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError as exc:
        raise MessageSignatureError("invalid hex signature") from exc

    verifying_key = _verifying_key_from_public_key(public_key)
    try:
        return verifying_key.verify_digest(
            signature,
            message_digest(message),
            sigdecode=sigdecode_der,
        )
    except BadSignatureError:
        return False

