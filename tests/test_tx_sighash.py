import unittest

from tx.codec import deserialize_transaction_hex
from tx.model import Prevout
from tx.sighash import bip143_sighash_all


class TransactionSighashTest(unittest.TestCase):
    def test_bip143_native_p2wpkh_published_vector(self):
        unsigned = (
            "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"
            "0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57"
            "b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c9"
            "5a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f01"
            "67faa815988ac11000000"
        )
        tx = deserialize_transaction_hex(unsigned)
        prevout = Prevout(
            txid=tx.inputs[1].txid,
            vout=tx.inputs[1].vout,
            value=600_000_000,
            script_pubkey=bytes.fromhex("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1"),
            address="vector-address",
            address_type="p2wpkh",
            derivation_path="m/84'/0'/0'/0/0",
        )
        self.assertEqual(
            bip143_sighash_all(tx, 1, prevout).hex(),
            "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670",
        )


if __name__ == "__main__":
    unittest.main()
