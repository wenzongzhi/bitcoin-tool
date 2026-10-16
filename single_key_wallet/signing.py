"""Fixed-key SIGHASH_ALL ECDSA signing and strict local verification."""

from copy import deepcopy
import struct

from coincurve import PrivateKey, PublicKey
from btc.btc_address_gen import hash160, p2pkh_script_pubkey, p2wpkh_script_pubkey
from .codec import compact_size, double_sha256, metrics, outpoint, serialize, serialize_output, varbytes
from .constants import ADDRESS_TYPE_P2PKH_UNCOMPRESSED, ADDRESS_TYPE_P2WPKH, SPEND_ADDRESS_TYPES
from .errors import SingleKeyTransactionError
from .models import Transaction
from .wif import validate_private_key


def sighash_all(tx: Transaction, input_index: int, prevout: dict) -> bytes:
    if not 0 <= input_index < len(tx.inputs):
        raise SingleKeyTransactionError("input index out of range")
    item = tx.inputs[input_index]
    if item.txid != prevout["txid"] or item.vout != prevout["vout"]:
        raise SingleKeyTransactionError("prevout does not match transaction input")
    script = bytes.fromhex(prevout["script_pubkey"])
    if prevout["address_type"] == ADDRESS_TYPE_P2WPKH:
        if len(script) != 22 or script[:2] != b"\x00\x14":
            raise SingleKeyTransactionError("invalid P2WPKH prevout")
        preimage = (
            struct.pack("<i", tx.version)
            + double_sha256(b"".join(outpoint(v) for v in tx.inputs))
            + double_sha256(b"".join(struct.pack("<I", v.sequence) for v in tx.inputs))
            + outpoint(item) + varbytes(b"\x76\xa9\x14" + script[2:] + b"\x88\xac")
            + struct.pack("<Q", prevout["value"]) + struct.pack("<I", item.sequence)
            + double_sha256(b"".join(serialize_output(v) for v in tx.outputs))
            + struct.pack("<II", tx.locktime, 1)
        )
    elif prevout["address_type"] in SPEND_ADDRESS_TYPES:
        if len(script) != 25 or script[:3] != b"\x76\xa9\x14" or script[-2:] != b"\x88\xac":
            raise SingleKeyTransactionError("invalid P2PKH prevout")
        unsigned = deepcopy(tx)
        for index, value in enumerate(unsigned.inputs):
            value.script_sig = script if index == input_index else b""
            value.witness = []
        preimage = serialize(unsigned, False) + struct.pack("<I", 1)
    else:
        raise SingleKeyTransactionError("spending not yet supported for source address type")
    return double_sha256(preimage)


def _script_pushes(script: bytes) -> list[bytes]:
    items, position = [], 0
    while position < len(script):
        length = script[position]
        position += 1
        if not 1 <= length <= 75 or position + length > len(script):
            raise ValueError
        items.append(script[position:position + length])
        position += length
    return items


def verify_all_inputs(tx: Transaction, prevouts: list[dict]) -> bool:
    if len(tx.inputs) != len(prevouts) or not prevouts:
        return False
    if len({v.get("address_type") for v in prevouts}) != 1:
        return False
    try:
        for index, (item, prevout) in enumerate(zip(tx.inputs, prevouts)):
            kind = prevout["address_type"]
            if kind == ADDRESS_TYPE_P2WPKH:
                if item.script_sig or len(item.witness) != 2:
                    return False
                signature, public = item.witness
                expected_script = p2wpkh_script_pubkey(public)
            else:
                if kind not in SPEND_ADDRESS_TYPES or item.witness:
                    return False
                signature, public = _script_pushes(item.script_sig)
                expected_script = p2pkh_script_pubkey(public)
            expected_length = 65 if kind == ADDRESS_TYPE_P2PKH_UNCOMPRESSED else 33
            if len(public) != expected_length or not signature or signature[-1] != 1:
                return False
            if PublicKey(public).format(compressed=expected_length == 33) != public:
                return False
            if expected_script != prevout["script_pubkey"]:
                return False
            if not PublicKey(public).verify(signature[:-1], sighash_all(tx, index, prevout), hasher=None):
                return False
    except (ValueError, TypeError, KeyError, SingleKeyTransactionError):
        return False
    return True


def sign_transaction(tx: Transaction, prevouts: list[dict], key: bytes) -> dict:
    validate_private_key(key)
    if not prevouts or len(prevouts) != len(tx.inputs) or len({v["address_type"] for v in prevouts}) != 1:
        raise SingleKeyTransactionError("mixed or invalid transaction input types")
    private = PrivateKey(key)
    try:
        for index, (item, prevout) in enumerate(zip(tx.inputs, prevouts)):
            kind = prevout["address_type"]
            if kind not in SPEND_ADDRESS_TYPES:
                raise SingleKeyTransactionError("spending not yet supported for source address type")
            public = private.public_key.format(compressed=kind != ADDRESS_TYPE_P2PKH_UNCOMPRESSED)
            expected_script = p2wpkh_script_pubkey(public) if kind == ADDRESS_TYPE_P2WPKH else p2pkh_script_pubkey(public)
            if expected_script != prevout["script_pubkey"]:
                raise SingleKeyTransactionError("selected input is not controlled by this private key")
            item.script_sig, item.witness = b"", []
            signature = private.sign(sighash_all(tx, index, prevout), hasher=None) + b"\x01"
            if kind == ADDRESS_TYPE_P2WPKH:
                item.witness = [signature, public]
            else:
                item.script_sig = bytes([len(signature)]) + signature + bytes([len(public)]) + public
        if not verify_all_inputs(tx, prevouts):
            raise SingleKeyTransactionError("local signature verification failed")
        return metrics(tx)
    finally:
        del private
