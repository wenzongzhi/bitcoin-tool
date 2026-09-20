import unittest

from tx.errors import TransactionError
from tx.script import (
    address_to_script_pubkey,
    classify_script_pubkey,
    script_pubkey_to_address,
)


class TransactionScriptTest(unittest.TestCase):
    CASES = (
        ("mainnet", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "p2pkh"),
        ("mainnet", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "p2wpkh"),
        ("testnet4", "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r", "p2pkh"),
        ("testnet4", "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", "p2wpkh"),
    )

    def test_supported_addresses_round_trip(self):
        for network, address, expected_type in self.CASES:
            with self.subTest(network=network, address=address):
                script = address_to_script_pubkey(address, network)
                self.assertEqual(classify_script_pubkey(script), expected_type)
                self.assertEqual(script_pubkey_to_address(script, network), address)

    def test_wrong_network_and_unsupported_address_are_rejected(self):
        with self.assertRaisesRegex(TransactionError, "does not belong"):
            address_to_script_pubkey(self.CASES[0][1], "testnet4")
        with self.assertRaises(TransactionError):
            address_to_script_pubkey("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", "mainnet")


if __name__ == "__main__":
    unittest.main()
