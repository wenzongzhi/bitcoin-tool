"""Fixed-key transaction models, with no HD derivation metadata."""

from dataclasses import dataclass, field
import re

from .constants import MAX_MONEY
from .errors import SingleKeyTransactionError


def integer(value, minimum=0, maximum=MAX_MONEY, label="value") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise SingleKeyTransactionError(f"{label} is outside the allowed integer range")
    return value


def txid(value) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-fA-F]{64}", value) is None:
        raise SingleKeyTransactionError("invalid transaction id")
    return value.lower()


@dataclass
class TxInput:
    txid: str
    vout: int
    sequence: int = 0xFFFFFFFD
    script_sig: bytes = b""
    witness: list[bytes] = field(default_factory=list)

    def __post_init__(self):
        self.txid = txid(self.txid)
        integer(self.vout, maximum=0xFFFFFFFF, label="vout")
        integer(self.sequence, maximum=0xFFFFFFFF, label="sequence")

    @property
    def outpoint(self):
        return f"{self.txid}:{self.vout}"


@dataclass
class TxOutput:
    value: int
    script_pubkey: bytes

    def __post_init__(self):
        integer(self.value, label="output value")
        if not isinstance(self.script_pubkey, bytes):
            raise SingleKeyTransactionError("invalid output script")


@dataclass
class Transaction:
    inputs: list[TxInput]
    outputs: list[TxOutput]
    version: int = 2
    locktime: int = 0

    def __post_init__(self):
        integer(self.version, -(2**31), 2**31 - 1, "version")
        integer(self.locktime, maximum=0xFFFFFFFF, label="locktime")
        points = [item.outpoint for item in self.inputs]
        if len(points) != len(set(points)):
            raise SingleKeyTransactionError("duplicate transaction inputs")
        integer(sum(item.value for item in self.outputs), label="total output")
