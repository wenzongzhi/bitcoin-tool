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

import hashlib

from ecdsa import BadSignatureError, MalformedPointError, SECP256k1, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_der, sigencode_der_canonize

from btc.btc_address_gen import is_valid_public_key, privkey_to_pubkey
from btc.private_key_gen import is_valid_privkey


class MessageSignatureError(Exception):
    pass


def message_digest(message: str) -> bytes:
    return hashlib.sha256(message.encode("utf-8")).digest()


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

