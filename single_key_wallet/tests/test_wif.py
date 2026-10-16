import unittest

from btc.btc_address_gen import base58check
from single_key_wallet import SingleKeyWalletError
from single_key_wallet.wif import decode_wif, encode_wif
from single_key_wallet.tests.helpers import KEY, COMPRESSED_WIF, UNCOMPRESSED_WIF


class WifTest(unittest.TestCase):
    def test_known_mainnet_vectors(self):
        self.assertEqual(decode_wif(COMPRESSED_WIF, "mainnet"), (KEY, True))
        self.assertEqual(decode_wif(UNCOMPRESSED_WIF, "mainnet"), (KEY, False))
        self.assertEqual(encode_wif(KEY, "mainnet"), COMPRESSED_WIF)
        self.assertEqual(encode_wif(KEY, "mainnet", False), UNCOMPRESSED_WIF)

    def test_testnet_markers_and_network(self):
        for compressed in (False, True):
            encoded = encode_wif(KEY, "testnet4", compressed)
            self.assertEqual(decode_wif(encoded, "testnet4"), (KEY, compressed))
            with self.assertRaises(SingleKeyWalletError):
                decode_wif(encoded, "mainnet")
        with self.assertRaises(SingleKeyWalletError):
            decode_wif(COMPRESSED_WIF, "testnet4")

    def test_invalid_checksum_payload_marker_and_scalar(self):
        values = [COMPRESSED_WIF[:-1] + "1", "invalid0", base58check(b"\x80", KEY + b"\x02"),
                  base58check(b"\x80", KEY[:-1]), base58check(b"\x80", b"\x00" * 32),
                  base58check(b"\x80", b"\xff" * 32)]
        for value in values:
            with self.subTest(length=len(value)), self.assertRaises(SingleKeyWalletError):
                decode_wif(value, "mainnet")
