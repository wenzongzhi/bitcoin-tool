from decimal import Decimal
import unittest

from single_key_wallet.coin_selection import estimate_signed_vsize, parse_fee_rate, select_coins
from single_key_wallet.constants import SPEND_ADDRESS_TYPES
from single_key_wallet.errors import SingleKeyTransactionError
from single_key_wallet.models import TxOutput

SCRIPT = b"\x00\x14" + b"\x12" * 20
LEGACY_SCRIPT = b"\x76\xa9\x14" + b"\x12" * 20 + b"\x88\xac"


def utxo(number, kind="p2wpkh", value=100_000, confirmed=True):
    return {"txid": f"{number:064x}", "vout": 0, "value": value,
            "address": "test-address", "address_type": kind,
            "script_pubkey": SCRIPT.hex() if kind == "p2wpkh" else LEGACY_SCRIPT.hex(),
            "confirmed": confirmed, "confirmations": 6 if confirmed else 0}


class CoinSelectionTest(unittest.TestCase):
    def test_distinct_input_size_estimates(self):
        output = [TxOutput(10_000, SCRIPT)]
        sizes = {kind: estimate_signed_vsize(1, kind, output) for kind in SPEND_ADDRESS_TYPES}
        self.assertGreater(sizes["p2pkh-uncompressed"], sizes["p2pkh-compressed"])
        self.assertEqual(sizes["p2pkh-uncompressed"] - sizes["p2pkh-compressed"], 32)
        self.assertGreater(sizes["p2pkh-compressed"], sizes["p2wpkh"])

    def test_fee_validation(self):
        self.assertEqual(parse_fee_rate("2.5"), Decimal("2.5"))
        for value in ("NaN", "Infinity", "0", "-1", "10001", "hello", True):
            with self.subTest(value=str(value)), self.assertRaises(SingleKeyTransactionError):
                parse_fee_rate(value)

    def test_all_excludes_other_types_unconfirmed_and_reserved(self):
        result = select_coins([utxo(1), utxo(2), utxo(3, "p2pkh-compressed"),
                               utxo(4, confirmed=False), utxo(5)],
                              "p2wpkh", "2", SCRIPT, SCRIPT, send_all=True,
                              unavailable={f"{5:064x}:0"})
        self.assertEqual(len(result["selected"]), 2)
        self.assertEqual(result["change_amount_sats"], 0)
        self.assertEqual(result["destination_amount_sats"], 200_000 - result["estimated_fee_sats"])

    def test_insufficient_dust_and_fee_limits(self):
        with self.assertRaisesRegex(SingleKeyTransactionError, "insufficient funds"):
            select_coins([utxo(1, value=1000)], "p2wpkh", "2", SCRIPT, SCRIPT, amount_sats=1000)
        with self.assertRaisesRegex(SingleKeyTransactionError, "dust"):
            select_coins([utxo(1)], "p2wpkh", "2", SCRIPT, SCRIPT, amount_sats=1)
        with self.assertRaisesRegex(SingleKeyTransactionError, "consumes"):
            select_coins([utxo(1, value=100)], "p2wpkh", "2", SCRIPT, SCRIPT, send_all=True)
        with self.assertRaisesRegex(SingleKeyTransactionError, "dust"):
            select_coins([utxo(1, value=400)], "p2wpkh", "2", SCRIPT, SCRIPT, send_all=True)
        with self.assertRaisesRegex(SingleKeyTransactionError, r"^estimated fee 220 sats exceeds max fee 219 sats$"):
            select_coins([utxo(1)], "p2wpkh", "2", SCRIPT, SCRIPT, send_all=True, max_fee_sats=219)

    def test_dust_change_absorbed_and_equal_max_accepted(self):
        result = select_coins([utxo(1, value=10_300)], "p2wpkh", "2", SCRIPT, SCRIPT, amount_sats=10_000, max_fee_sats=300)
        self.assertEqual(result["estimated_fee_sats"], 300)
        self.assertEqual(result["change_amount_sats"], 0)

    def test_confirmation_and_amount_mode_rules(self):
        for options in ({}, {"send_all": True, "amount_sats": 1000}, {"send_all": True, "min_confirmations": 0}):
            with self.assertRaises(SingleKeyTransactionError):
                select_coins([utxo(1)], "p2wpkh", "1", SCRIPT, SCRIPT, **options)
