from copy import deepcopy
import unittest

from single_key_wallet.codec import deserialize, metrics, serialize
from single_key_wallet.constants import SPEND_ADDRESS_TYPES
from single_key_wallet.models import Transaction, TxInput, TxOutput
from single_key_wallet.signing import sign_transaction, sighash_all, verify_all_inputs, _script_pushes
from single_key_wallet.wallet import public_metadata
from coincurve import PrivateKey
from single_key_wallet.tests.helpers import KEY


class SigningTest(unittest.TestCase):
    def test_bip143_official_published_digest(self):
        unsigned = (
            "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f"
            "0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57"
            "b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c9"
            "5a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f01"
            "67faa815988ac11000000"
        )
        tx = deserialize(unsigned)
        prevout = {"txid": tx.inputs[1].txid, "vout": tx.inputs[1].vout, "value": 600_000_000,
                   "script_pubkey": "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1", "address_type": "p2wpkh"}
        self.assertEqual(sighash_all(tx, 1, prevout).hex(), "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670")

    def test_all_three_paths_and_tampered_message(self):
        addresses = public_metadata(PrivateKey(KEY).public_key.format(), "mainnet")["addresses"]
        for kind in SPEND_ADDRESS_TYPES:
            with self.subTest(kind=kind):
                source = addresses[kind]
                prevout = {"txid": "ab" * 32, "vout": 1, "value": 100_000,
                           "address_type": kind, "script_pubkey": source["script_pubkey"]}
                tx = Transaction([TxInput(prevout["txid"], 1)], [TxOutput(99_000, bytes.fromhex(source["script_pubkey"]))])
                sign_transaction(tx, [prevout], KEY)
                self.assertTrue(verify_all_inputs(tx, [prevout]))
                if kind == "p2wpkh":
                    self.assertEqual(tx.inputs[0].script_sig, b"")
                    signature, public = tx.inputs[0].witness
                    self.assertEqual(len(public), 33)
                else:
                    self.assertEqual(tx.inputs[0].witness, [])
                    signature, public = _script_pushes(tx.inputs[0].script_sig)
                    self.assertEqual(len(public), 65 if kind == "p2pkh-uncompressed" else 33)
                self.assertEqual(signature[-1], 1)
                self.assertEqual(serialize(deserialize(serialize(tx).hex())), serialize(tx))
                changed = deepcopy(tx)
                changed.outputs[0].value += 1
                self.assertFalse(verify_all_inputs(changed, [prevout]))
                changed = deepcopy(tx)
                changed.inputs[0].vout += 1
                self.assertFalse(verify_all_inputs(changed, [prevout]))
