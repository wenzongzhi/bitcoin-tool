from copy import deepcopy
import json
import os
from unittest.mock import patch

from coincurve import PublicKey

from single_key_wallet import SingleKeyWalletError, SingleKeyWalletService
from single_key_wallet.constants import CURVE_ORDER, SPEND_ADDRESS_TYPES, SYNC_ADDRESS_TYPES
from single_key_wallet.storage import default_single_key_cache_file, default_single_key_wallet_file, write_json
from single_key_wallet.wallet import load_wallet, unlock_private_key
from single_key_wallet.wif import parse_private_key_hex
from single_key_wallet.tests.helpers import WalletFixture, KEY, KEY_HEX, UNCOMPRESSED_WIF, assert_no_secret_fields


class WalletTest(WalletFixture):
    def test_known_mainnet_keys_and_five_addresses(self):
        service = SingleKeyWalletService(self.directory / "main.json", self.directory / "main-cache.json")
        created = service.import_private_key_hex("known", KEY_HEX)
        expected = {
            "p2pkh-compressed": "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            "p2pkh-uncompressed": "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm",
            "p2wpkh": "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "p2sh-p2wpkh": "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN",
            "p2tr": "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9",
        }
        self.assertEqual({k: v["address"] for k, v in created["addresses"].items()}, expected)
        self.assertEqual(len(bytes.fromhex(created["public_keys"]["compressed"])), 33)
        self.assertEqual(len(bytes.fromhex(created["public_keys"]["uncompressed"])), 65)
        self.assertEqual(created["public_keys"]["xonly"], created["public_keys"]["compressed"][2:])
        self.assertEqual(created["public_keys"]["taproot_output_key"], created["addresses"]["p2tr"]["script_pubkey"][4:])
        for kind in SYNC_ADDRESS_TYPES:
            self.assertNotEqual(created["addresses"][kind]["address"], self.addresses[kind]["address"])

    def test_generation_and_capability_matrix(self):
        result = self.service.create_wallet("generated", "password")
        record = load_wallet("generated", self.wallet_file, "testnet4")
        key = unlock_private_key("generated", record, "password")
        self.assertEqual(len(key), 32)
        self.assertEqual(result["key_origin"], {"type": "generated", "wif_compressed": None})
        for kind, entry in result["addresses"].items():
            self.assertTrue(entry["sync_supported"])
            self.assertEqual(entry["receive_supported"], kind in SPEND_ADDRESS_TYPES)
            self.assertEqual(entry["spend_supported"], kind in SPEND_ADDRESS_TYPES)
        self.assertEqual(self.service.get_receive_address("generated")["address_type"], "p2wpkh")

    def test_hex_validation(self):
        valid = f"{10:064x}"
        self.assertEqual(parse_private_key_hex(valid.upper()), parse_private_key_hex(valid))
        for invalid in ("gg" * 32, "01", "0" * 64, f"{CURVE_ORDER:064x}", " " + KEY_HEX, KEY_HEX + "00"):
            with self.subTest(invalid_length=len(invalid)), self.assertRaises(SingleKeyWalletError):
                parse_private_key_hex(invalid)

    def test_encryption_wrong_password_and_corruption(self):
        record = load_wallet("test", self.wallet_file, "testnet4")
        self.assertEqual(unlock_private_key("test", record, "password"), KEY)
        self.assertNotIn(KEY_HEX, self.wallet_file.read_text())
        with self.assertRaises(SingleKeyWalletError):
            unlock_private_key("test", record, "wrong")
        corrupt = deepcopy(record)
        ciphertext = corrupt["secret"]["encryption"]["ciphertext"]
        corrupt["secret"]["encryption"]["ciphertext"] = ("00" if ciphertext[:2] != "00" else "01") + ciphertext[2:]
        with self.assertRaises(SingleKeyWalletError):
            unlock_private_key("test", corrupt, "password")
        corrupt = deepcopy(record)
        corrupt["secret"]["encryption"]["iterations"] = 10**9
        with self.assertRaises(SingleKeyWalletError):
            unlock_private_key("test", corrupt, "password")

    def test_duplicate_name_password_change_and_plaintext(self):
        with self.assertRaises(SingleKeyWalletError):
            self.service.create_wallet("test")
        self.service.change_password("test", "password", "new")
        record = load_wallet("test", self.wallet_file, "testnet4")
        with self.assertRaises(SingleKeyWalletError):
            unlock_private_key("test", record, "password")
        self.assertEqual(unlock_private_key("test", record, "new"), KEY)
        self.service.change_password("test", "new", None)
        record = load_wallet("test", self.wallet_file, "testnet4")
        self.assertFalse(record["encrypted"])
        self.assertEqual(record["secret"], {"format": "raw-private-key", "private_key_hex": KEY_HEX})
        self.service.remove_wallet("test")
        self.assertEqual(self.service.list_wallets(), [])

    def test_uncompressed_wif_historical_default(self):
        service = SingleKeyWalletService(self.directory / "legacy.json", self.directory / "legacy-cache.json")
        created = service.import_private_key_wif("old", UNCOMPRESSED_WIF, "pass")
        self.assertEqual(created["key_origin"], {"type": "wif", "wif_compressed": False})
        self.assertEqual(created["preferences"]["default_legacy_pubkey_format"], "uncompressed")
        received = service.get_receive_address("old")
        self.assertEqual(received["address_type"], "p2pkh-uncompressed")
        self.assertEqual(received["address"], "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm")
        self.assertEqual(len(created["addresses"]), 5)
        self.assertEqual(service.get_receive_address("old"), received)
        with self.assertRaises(SingleKeyWalletError):
            service.get_receive_address("old", "p2tr")

    def test_public_apis_never_return_secrets_or_hd_fields(self):
        for result in (self.service.list_wallets(), self.service.get_wallet_state("test"), self.service.get_addresses("test")):
            assert_no_secret_fields(self, result)
        # Public-key substitution must fail authenticated decryption too.
        record = load_wallet("test", self.wallet_file, "testnet4")
        record["preferences"]["default_receive_address_type"] = "p2pkh-compressed"
        with self.assertRaises(SingleKeyWalletError):
            unlock_private_key("test", record, "password")

    def test_paths_and_network_isolation(self):
        with patch.dict(os.environ, {"BITCOIN_TOOL_DATADIR": str(self.directory)}):
            main = default_single_key_wallet_file(network="mainnet")
            test = default_single_key_wallet_file(network="testnet4")
            self.assertEqual(main.name, "single_key_wallets.json")
            self.assertEqual(test.name, "single_key_wallets_testnet4.json")
            self.assertEqual(default_single_key_cache_file(network="testnet4").name, "single_key_wallet_cache_testnet4.json")
            self.assertNotEqual(main, test)
        with self.assertRaises(SingleKeyWalletError):
            load_wallet("test", self.wallet_file, "mainnet")
