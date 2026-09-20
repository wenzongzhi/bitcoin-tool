import unittest

from tx.codec import (
    ByteReader,
    decode_compact_size,
    deserialize_transaction_hex,
    encode_compact_size,
    serialize_transaction_hex,
    transaction_metrics,
)
from tx.errors import TransactionError
from tx.model import Transaction, TxInput, TxOutput


class TransactionCodecTest(unittest.TestCase):
    def test_compact_size_boundaries(self):
        values = (0, 252, 253, 65535, 65536, 0xFFFFFFFF, 0x100000000, 0xFFFFFFFFFFFFFFFF)
        for value in values:
            with self.subTest(value=value):
                encoded = encode_compact_size(value)
                decoded, offset = decode_compact_size(encoded)
                self.assertEqual(decoded, value)
                self.assertEqual(offset, len(encoded))

    def test_compact_size_rejects_noncanonical_and_truncated_values(self):
        for encoded in (b"\xfd\xfc\x00", b"\xfe\xff\xff\x00\x00", b"\xff\xff\xff\xff\xff\x00\x00\x00\x00", b"\xfd\x01"):
            with self.subTest(encoded=encoded.hex()):
                with self.assertRaises(TransactionError):
                    ByteReader(encoded).read_compact_size()

    def test_legacy_and_segwit_round_trip(self):
        legacy = Transaction(
            2,
            [TxInput("11" * 32, 1, script_sig=b"\x01\x01")],
            [TxOutput(5000, bytes.fromhex("76a914" + "22" * 20 + "88ac"))],
            0,
        )
        segwit = Transaction(
            2,
            [TxInput("33" * 32, 2, witness=[b"signature", b"public-key"])],
            [TxOutput(4000, bytes.fromhex("0014" + "44" * 20))],
            9,
        )
        for transaction in (legacy, segwit):
            with self.subTest(segwit=transaction.has_witness):
                raw = serialize_transaction_hex(transaction)
                parsed = deserialize_transaction_hex(raw)
                self.assertEqual(serialize_transaction_hex(parsed), raw)
                metrics = transaction_metrics(parsed)
                self.assertEqual(metrics["segwit"], transaction.has_witness)
                self.assertGreater(metrics["vsize"], 0)

    def test_genesis_coinbase_txid_and_round_trip(self):
        raw = (
            "01000000010000000000000000000000000000000000000000000000000000000000000000"
            "ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f3230303920436861"
            "6e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f"
            "722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7"
            "105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7"
            "ba0b8d578a4c702b6bf11d5fac00000000"
        )
        transaction = deserialize_transaction_hex(raw)
        self.assertEqual(serialize_transaction_hex(transaction), raw)
        metrics = transaction_metrics(transaction)
        self.assertEqual(
            metrics["txid"],
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        )
        self.assertEqual(metrics["wtxid"], metrics["txid"])


if __name__ == "__main__":
    unittest.main()
