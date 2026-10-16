"""Canonical Bitcoin transaction serialization independent of the HD tx package."""

import hashlib
import struct

from .errors import SingleKeyTransactionError
from .models import Transaction, TxInput, TxOutput, integer


def double_sha256(value: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(value).digest()).digest()


def compact_size(value: int) -> bytes:
    integer(value, maximum=0xFFFFFFFFFFFFFFFF, label="CompactSize")
    if value < 253:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def varbytes(value: bytes) -> bytes:
    return compact_size(len(value)) + value


def outpoint(item: TxInput) -> bytes:
    return bytes.fromhex(item.txid)[::-1] + struct.pack("<I", item.vout)


def serialize_output(item: TxOutput) -> bytes:
    return struct.pack("<Q", item.value) + varbytes(item.script_pubkey)


def serialize(tx: Transaction, include_witness=True) -> bytes:
    witness = include_witness and any(item.witness for item in tx.inputs)
    result = struct.pack("<i", tx.version) + (b"\x00\x01" if witness else b"")
    result += compact_size(len(tx.inputs))
    result += b"".join(outpoint(item) + varbytes(item.script_sig) + struct.pack("<I", item.sequence) for item in tx.inputs)
    result += compact_size(len(tx.outputs)) + b"".join(serialize_output(item) for item in tx.outputs)
    if witness:
        result += b"".join(compact_size(len(item.witness)) + b"".join(varbytes(v) for v in item.witness) for item in tx.inputs)
    return result + struct.pack("<I", tx.locktime)


def metrics(tx: Transaction) -> dict:
    raw, stripped = serialize(tx), serialize(tx, False)
    weight = len(stripped) * 3 + len(raw)
    return {
        "txid": double_sha256(stripped)[::-1].hex(),
        "wtxid": double_sha256(raw)[::-1].hex(),
        "size": len(raw), "weight": weight, "vsize": (weight + 3) // 4,
    }


def deserialize(raw_hex: str) -> Transaction:
    try:
        if not isinstance(raw_hex, str) or len(raw_hex) > 800_000 or len(raw_hex) % 2:
            raise ValueError
        raw = bytes.fromhex(raw_hex)
    except (TypeError, ValueError) as exc:
        raise SingleKeyTransactionError("invalid raw transaction encoding") from exc
    position = 0

    def read(count):
        nonlocal position
        if count < 0 or position + count > len(raw):
            raise SingleKeyTransactionError("truncated raw transaction")
        value = raw[position:position + count]
        position += count
        return value

    def size():
        marker = read(1)[0]
        if marker < 253:
            return marker
        count, minimum = {253: (2, 253), 254: (4, 65536), 255: (8, 2**32)}[marker]
        value = int.from_bytes(read(count), "little")
        if value < minimum or value > len(raw):
            raise SingleKeyTransactionError("invalid CompactSize")
        return value

    version = int.from_bytes(read(4), "little", signed=True)
    witness = raw[position:position + 2] == b"\x00\x01"
    if witness:
        read(2)
    count = size()
    if count == 0:
        raise SingleKeyTransactionError("transaction has no inputs")
    inputs = []
    for _ in range(count):
        identifier = read(32)[::-1].hex()
        vout = int.from_bytes(read(4), "little")
        script = read(size())
        sequence = int.from_bytes(read(4), "little")
        inputs.append(TxInput(identifier, vout, sequence, script))
    outputs = []
    for _ in range(size()):
        value = int.from_bytes(read(8), "little")
        outputs.append(TxOutput(value, read(size())))
    if witness:
        for item in inputs:
            item.witness = [read(size()) for _ in range(size())]
    locktime = int.from_bytes(read(4), "little")
    tx = Transaction(inputs, outputs, version, locktime)
    if position != len(raw) or serialize(tx) != raw:
        raise SingleKeyTransactionError("noncanonical raw transaction")
    return tx
