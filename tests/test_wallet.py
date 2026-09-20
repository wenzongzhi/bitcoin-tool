import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from btc.chainparams import NETWORK_TESTNET4
from wallet.wallet import (
    WalletError,
    create_wallet,
    default_wallet_file,
    derive_p2wpkh_from_account_xpub,
    entropy_hex_from_mnemonic,
    export_account_xpub,
    get_wallet_address_book,
    get_mnemonic,
    get_new_address,
    get_wallet_signing_key,
    mnemonic_from_entropy_hex,
    rebuild_address_book,
)


ZERO_ENTROPY = "00" * 32
ZERO_ENTROPY_MNEMONIC = " ".join(["abandon"] * 23 + ["art"])


class WalletTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.wallet_file = Path(self.temp_dir.name) / "wallets.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_encrypted_wallet_and_sequential_addresses(self):
        result = create_wallet(
            "my_BTC_01",
            password="correct-password",
            entropy_hex=ZERO_ENTROPY,
            wallet_file=self.wallet_file,
        )
        self.assertIsNone(result["mnemonic"])

        stored = json.loads(self.wallet_file.read_text(encoding="utf-8"))
        wallet = stored["my_BTC_01"]
        self.assertTrue(wallet["encrypted"])
        self.assertEqual(wallet["version"], 3)
        self.assertEqual(wallet["network"], "mainnet")
        self.assertRegex(wallet["master_fingerprint"], r"^[0-9a-f]{8}$")
        for old_root_field in (
            "address_type",
            "account_derivation_path",
            "account_xpub",
            "receive_branch",
            "change_branch",
            "next_receive_index",
            "next_change_index",
            "issued_addresses",
        ):
            self.assertNotIn(old_root_field, wallet)
        self.assertEqual(
            set(wallet["accounts"]),
            {
                "bip44-account-0",
                "bip49-account-0",
                "bip84-account-0",
                "bip86-account-0",
            },
        )
        p2wpkh_account = wallet["accounts"]["bip84-account-0"]
        self.assertEqual(p2wpkh_account["address_type"], "P2WPKH")
        self.assertEqual(p2wpkh_account["account_derivation_path"], "m/84'/0'/0'")
        self.assertTrue(p2wpkh_account["account_xpub"].startswith("xpub"))
        self.assertEqual(p2wpkh_account["receive_branch"], 0)
        self.assertEqual(p2wpkh_account["change_branch"], 1)
        self.assertEqual(p2wpkh_account["next_receive_index"], 0)
        self.assertEqual(p2wpkh_account["next_change_index"], 0)
        self.assertNotIn("mnemonic", wallet)
        self.assertNotIn(ZERO_ENTROPY_MNEMONIC, self.wallet_file.read_text(encoding="utf-8"))
        keys = list(wallet)
        self.assertLess(keys.index("encryption"), keys.index("accounts"))
        self.assertEqual(
            get_mnemonic(
                "my_BTC_01",
                "correct-password",
                wallet_file=self.wallet_file,
            )["mnemonic"],
            ZERO_ENTROPY_MNEMONIC,
        )

        first = get_new_address(
            "my_BTC_01",
            wallet_file=self.wallet_file,
        )
        second = get_new_address(
            "my_BTC_01",
            wallet_file=self.wallet_file,
        )
        change = get_new_address(
            "my_BTC_01",
            wallet_file=self.wallet_file,
            change=True,
        )
        self.assertTrue(first["address"].startswith("bc1q"))
        self.assertTrue(second["address"].startswith("bc1q"))
        self.assertTrue(change["address"].startswith("bc1q"))
        self.assertNotEqual(first["address"], second["address"])
        self.assertNotEqual(first["address"], change["address"])
        self.assertEqual(first["relative_derivation_path"], "m/0/0")
        self.assertEqual(first["purpose"], "receive")
        self.assertEqual(change["relative_derivation_path"], "m/1/0")
        self.assertEqual(change["purpose"], "change")
        self.assertEqual(first["derivation_path"], "m/84'/0'/0'/0/0")
        self.assertEqual(second["derivation_path"], "m/84'/0'/0'/0/1")
        self.assertEqual(change["derivation_path"], "m/84'/0'/0'/1/0")

        stored = json.loads(self.wallet_file.read_text(encoding="utf-8"))
        issued = stored["my_BTC_01"]["accounts"]["bip84-account-0"]["issued_addresses"]
        self.assertEqual([(entry["branch"], entry["index"]) for entry in issued], [(0, 0), (0, 1), (1, 0)])
        self.assertEqual(issued[0]["address"], first["address"])
        self.assertEqual(issued[0]["purpose"], "receive")
        self.assertEqual(issued[2]["purpose"], "change")
        self.assertEqual(len(issued[0]["script_pubkey"]), 44)
        self.assertFalse(issued[0]["used"])
        self.assertEqual(issued[0]["label"], "")
        self.assertRegex(issued[0]["created_at"], r"^\d{4}-\d{2}-\d{2}T.*Z$")

        exported = export_account_xpub(
            "my_BTC_01",
            "correct-password",
            wallet_file=self.wallet_file,
        )
        self.assertEqual(exported["account_xpub"], p2wpkh_account["account_xpub"])
        self.assertEqual(
            derive_p2wpkh_from_account_xpub(exported["account_xpub"], 0, 0),
            first["address"],
        )
        self.assertIn("/84'/0'/0']", exported["descriptor_like"])

    def test_address_types_use_independent_accounts_and_indexes(self):
        create_wallet("multi", entropy_hex=ZERO_ENTROPY, wallet_file=self.wallet_file)
        expectations = {
            "p2pkh": ("bip44-account-0", "m/44'/0'/0'/0/0", "1", 50),
            "p2sh-p2wpkh": ("bip49-account-0", "m/49'/0'/0'/0/0", "3", 46),
            "p2wpkh": ("bip84-account-0", "m/84'/0'/0'/0/0", "bc1q", 44),
            "p2tr": ("bip86-account-0", "m/86'/0'/0'/0/0", "bc1p", 68),
        }

        results = {}
        for address_type, (account_id, path, prefix, _) in expectations.items():
            result = get_new_address(
                "multi",
                wallet_file=self.wallet_file,
                address_type=address_type,
            )
            results[address_type] = result
            self.assertEqual(result["account_id"], account_id)
            self.assertEqual(result["derivation_path"], path)
            self.assertTrue(result["address"].startswith(prefix))
            self.assertEqual(result["index"], 0)

        change = get_new_address(
            "multi",
            wallet_file=self.wallet_file,
            address_type="p2pkh",
            change=True,
        )
        self.assertEqual(change["derivation_path"], "m/44'/0'/0'/1/0")

        stored = json.loads(self.wallet_file.read_text(encoding="utf-8"))["multi"]
        for address_type, (account_id, _, _, script_length) in expectations.items():
            account = stored["accounts"][account_id]
            self.assertEqual(account["next_receive_index"], 1)
            self.assertEqual(len(account["issued_addresses"][0]["script_pubkey"]), script_length)
        self.assertEqual(
            stored["accounts"]["bip44-account-0"]["next_change_index"],
            1,
        )
        change_entry = stored["accounts"]["bip44-account-0"]["issued_addresses"][1]
        self.assertEqual(
            set(change_entry),
            {
                "index",
                "branch",
                "relative_path",
                "path",
                "address",
                "script_pubkey",
                "purpose",
                "used",
                "label",
                "created_at",
            },
        )
        self.assertNotIn("lifecycle_state", change_entry)
        self.assertNotIn("issued_by_draft_id", change_entry)
        self.assertEqual(
            stored["accounts"]["bip84-account-0"]["next_change_index"],
            0,
        )

        address_book = get_wallet_address_book("multi", wallet_file=self.wallet_file)
        self.assertEqual(address_book["account_count"], 4)
        self.assertEqual(address_book["address_count"], 5)
        self.assertEqual(
            {entry["address_type"] for entry in address_book["addresses"]},
            {"P2PKH", "P2SH-P2WPKH", "P2WPKH", "P2TR"},
        )

        descriptors = {
            address_type: export_account_xpub(
                "multi",
                wallet_file=self.wallet_file,
                address_type=address_type,
            )["descriptor_like"]
            for address_type in expectations
        }
        self.assertTrue(descriptors["p2pkh"].startswith("pkh("))
        self.assertTrue(descriptors["p2sh-p2wpkh"].startswith("sh(wpkh("))
        self.assertTrue(descriptors["p2wpkh"].startswith("wpkh("))
        self.assertTrue(descriptors["p2tr"].startswith("tr("))

        legacy_signing_key = get_wallet_signing_key(
            "multi",
            results["p2pkh"]["derivation_path"],
            wallet_file=self.wallet_file,
        )
        self.assertEqual(legacy_signing_key["address"], results["p2pkh"]["address"])
        self.assertEqual(legacy_signing_key["address_type"], "P2PKH")

    def test_testnet4_wallet_uses_separate_file_and_network_parameters(self):
        testnet_wallet_file = default_wallet_file(
            self.temp_dir.name,
            NETWORK_TESTNET4,
        )
        result = create_wallet(
            "testnet_wallet",
            entropy_hex=ZERO_ENTROPY,
            wallet_file=testnet_wallet_file,
            network=NETWORK_TESTNET4,
        )
        self.assertEqual(result["network"], NETWORK_TESTNET4)
        self.assertEqual(testnet_wallet_file.name, "wallets_testnet4.json")
        self.assertFalse(self.wallet_file.exists())

        stored = json.loads(testnet_wallet_file.read_text(encoding="utf-8"))
        wallet = stored["testnet_wallet"]
        self.assertEqual(wallet["version"], 3)
        self.assertEqual(wallet["network"], NETWORK_TESTNET4)
        expected_paths = {
            "bip44-account-0": "m/44'/1'/0'",
            "bip49-account-0": "m/49'/1'/0'",
            "bip84-account-0": "m/84'/1'/0'",
            "bip86-account-0": "m/86'/1'/0'",
        }
        for account_id, account_path in expected_paths.items():
            account = wallet["accounts"][account_id]
            self.assertEqual(account["coin_type"], 1)
            self.assertEqual(account["account_derivation_path"], account_path)
            self.assertTrue(account["account_xpub"].startswith("tpub"))

        expectations = {
            "p2pkh": (("m", "n"), "m/44'/1'/0'/0/0"),
            "p2sh-p2wpkh": (("2",), "m/49'/1'/0'/0/0"),
            "p2wpkh": (("tb1q",), "m/84'/1'/0'/0/0"),
            "p2tr": (("tb1p",), "m/86'/1'/0'/0/0"),
        }
        issued = {}
        for address_type, (prefixes, derivation_path) in expectations.items():
            address = get_new_address(
                "testnet_wallet",
                wallet_file=testnet_wallet_file,
                address_type=address_type,
                network=NETWORK_TESTNET4,
            )
            issued[address_type] = address
            self.assertTrue(address["address"].startswith(prefixes))
            self.assertEqual(address["derivation_path"], derivation_path)

        self.assertEqual(
            get_mnemonic(
                "testnet_wallet",
                wallet_file=testnet_wallet_file,
                network=NETWORK_TESTNET4,
            )["mnemonic"],
            ZERO_ENTROPY_MNEMONIC,
        )
        exported = export_account_xpub(
            "testnet_wallet",
            wallet_file=testnet_wallet_file,
            network=NETWORK_TESTNET4,
        )
        self.assertTrue(exported["account_xpub"].startswith("tpub"))
        self.assertIn("/84'/1'/0']", exported["descriptor_like"])
        self.assertEqual(
            derive_p2wpkh_from_account_xpub(
                exported["account_xpub"],
                0,
                0,
                NETWORK_TESTNET4,
            ),
            issued["p2wpkh"]["address"],
        )

        address_book = get_wallet_address_book(
            "testnet_wallet",
            wallet_file=testnet_wallet_file,
            network=NETWORK_TESTNET4,
        )
        self.assertEqual(address_book["network"], NETWORK_TESTNET4)
        self.assertEqual(address_book["address_count"], 4)
        rebuild_address_book(
            "testnet_wallet",
            wallet_file=testnet_wallet_file,
            network=NETWORK_TESTNET4,
        )
        signing_key = get_wallet_signing_key(
            "testnet_wallet",
            issued["p2wpkh"]["derivation_path"],
            wallet_file=testnet_wallet_file,
            network=NETWORK_TESTNET4,
        )
        self.assertEqual(signing_key["address"], issued["p2wpkh"]["address"])

        with self.assertRaisesRegex(WalletError, "expected \"mainnet\""):
            get_new_address("testnet_wallet", wallet_file=testnet_wallet_file)

    def test_mnemonic_entropy_conversion(self):
        self.assertEqual(mnemonic_from_entropy_hex(ZERO_ENTROPY), ZERO_ENTROPY_MNEMONIC)
        self.assertEqual(entropy_hex_from_mnemonic(ZERO_ENTROPY_MNEMONIC), ZERO_ENTROPY)
        with self.assertRaisesRegex(WalletError, "mnemonic is invalid"):
            entropy_hex_from_mnemonic("abandon abandon abandon")

    def test_create_wallet_from_mnemonic(self):
        create_wallet(
            "from_entropy",
            entropy_hex=ZERO_ENTROPY,
            wallet_file=self.wallet_file,
        )
        create_wallet(
            "from_mnemonic",
            mnemonic=ZERO_ENTROPY_MNEMONIC,
            wallet_file=self.wallet_file,
        )
        from_entropy = get_new_address("from_entropy", wallet_file=self.wallet_file)
        from_mnemonic = get_new_address("from_mnemonic", wallet_file=self.wallet_file)
        self.assertEqual(from_mnemonic["address"], from_entropy["address"])

    def test_create_wallet_rejects_entropy_and_mnemonic_together(self):
        with self.assertRaisesRegex(WalletError, "mutually exclusive"):
            create_wallet(
                "conflict",
                entropy_hex=ZERO_ENTROPY,
                mnemonic=ZERO_ENTROPY_MNEMONIC,
                wallet_file=self.wallet_file,
            )

    def test_private_operations_require_the_correct_password(self):
        create_wallet("encrypted", "correct", ZERO_ENTROPY, self.wallet_file)
        first = get_new_address("encrypted", wallet_file=self.wallet_file)
        self.assertTrue(first["address"].startswith("bc1q"))

        stored = json.loads(self.wallet_file.read_text(encoding="utf-8"))
        self.assertEqual(
            stored["encrypted"]["accounts"]["bip84-account-0"]["next_receive_index"],
            1,
        )

        with self.assertRaisesRegex(WalletError, "incorrect password"):
            get_mnemonic("encrypted", "wrong", self.wallet_file)
        with self.assertRaisesRegex(WalletError, "password is required"):
            get_mnemonic("encrypted", wallet_file=self.wallet_file)
        with self.assertRaisesRegex(WalletError, "incorrect password"):
            export_account_xpub("encrypted", "wrong", self.wallet_file)
        with self.assertRaisesRegex(WalletError, "password is required"):
            export_account_xpub("encrypted", wallet_file=self.wallet_file)

    def test_wallet_signing_key_must_be_an_issued_path(self):
        create_wallet("signer", "correct", ZERO_ENTROPY, self.wallet_file)
        issued = get_new_address("signer", wallet_file=self.wallet_file)

        signing_key = get_wallet_signing_key(
            "signer",
            issued["derivation_path"],
            "correct",
            self.wallet_file,
        )
        self.assertEqual(signing_key["address"], issued["address"])
        self.assertEqual(signing_key["account_id"], "bip84-account-0")
        self.assertEqual(signing_key["address_type"], "P2WPKH")
        self.assertRegex(signing_key["private_key_hex"], r"^[0-9a-f]{64}$")

        with self.assertRaisesRegex(WalletError, "incorrect password"):
            get_wallet_signing_key(
                "signer",
                issued["derivation_path"],
                "wrong",
                self.wallet_file,
            )
        with self.assertRaisesRegex(WalletError, "not a unique issued"):
            get_wallet_signing_key(
                "signer",
                "m/84'/0'/0'/0/1",
                "correct",
                self.wallet_file,
            )

    def test_plaintext_wallet(self):
        create_wallet("plaintext", entropy_hex=ZERO_ENTROPY, wallet_file=self.wallet_file)
        stored = json.loads(self.wallet_file.read_text(encoding="utf-8"))
        self.assertFalse(stored["plaintext"]["encrypted"])
        self.assertEqual(stored["plaintext"]["mnemonic"], ZERO_ENTROPY_MNEMONIC)

        result = get_new_address("plaintext", wallet_file=self.wallet_file)
        self.assertTrue(result["address"].startswith("bc1q"))
        self.assertEqual(
            get_mnemonic("plaintext", wallet_file=self.wallet_file)["mnemonic"],
            ZERO_ENTROPY_MNEMONIC,
        )

    def test_duplicate_wallet_is_rejected(self):
        create_wallet("duplicate", entropy_hex=ZERO_ENTROPY, wallet_file=self.wallet_file)
        with self.assertRaisesRegex(WalletError, "already exists"):
            create_wallet("duplicate", entropy_hex=ZERO_ENTROPY, wallet_file=self.wallet_file)

    def test_invalid_entropy_is_rejected(self):
        with self.assertRaisesRegex(WalletError, "64 hex characters"):
            create_wallet("bad", entropy_hex="00", wallet_file=self.wallet_file)

    def test_rebuild_address_book_preserves_metadata(self):
        create_wallet("rebuilder", entropy_hex=ZERO_ENTROPY, wallet_file=self.wallet_file)
        first = get_new_address("rebuilder", wallet_file=self.wallet_file)
        second = get_new_address("rebuilder", wallet_file=self.wallet_file)

        stored = json.loads(self.wallet_file.read_text(encoding="utf-8"))
        account = stored["rebuilder"]["accounts"]["bip84-account-0"]
        first_entry = account["issued_addresses"][0]
        first_entry["label"] = "donation"
        account["issued_addresses"] = [first_entry]
        self.wallet_file.write_text(json.dumps(stored), encoding="utf-8")

        result = rebuild_address_book("rebuilder", wallet_file=self.wallet_file)
        self.assertEqual(result["address_count"], 2)
        self.assertEqual(result["recovered_count"], 1)

        rebuilt_wallet = json.loads(self.wallet_file.read_text(encoding="utf-8"))["rebuilder"]
        rebuilt = rebuilt_wallet["accounts"]["bip84-account-0"]
        self.assertEqual(rebuilt["issued_addresses"][0]["label"], "donation")
        self.assertNotIn("recovered_at", rebuilt["issued_addresses"][0])
        self.assertEqual(rebuilt["issued_addresses"][1]["address"], second["address"])
        self.assertEqual(len(rebuilt["issued_addresses"][1]["script_pubkey"]), 44)
        self.assertFalse(rebuilt["issued_addresses"][1]["used"])
        self.assertIsNone(rebuilt["issued_addresses"][1]["created_at"])
        self.assertIn("recovered_at", rebuilt["issued_addresses"][1])
        self.assertEqual(rebuilt["issued_addresses"][0]["address"], first["address"])

    def test_concurrent_address_requests_do_not_reuse_an_index(self):
        create_wallet("concurrent", entropy_hex=ZERO_ENTROPY, wallet_file=self.wallet_file)

        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(
                executor.map(
                    lambda _: get_new_address("concurrent", wallet_file=self.wallet_file),
                    range(4),
                )
            )

        self.assertEqual(sorted(result["index"] for result in results), [0, 1, 2, 3])
        self.assertEqual(len({result["address"] for result in results}), 4)

    def test_version_2_wallet_is_rejected_without_migration(self):
        create_wallet("old_format", "correct", ZERO_ENTROPY, self.wallet_file)
        stored = json.loads(self.wallet_file.read_text(encoding="utf-8"))
        wallet = stored["old_format"]
        wallet["version"] = 2
        self.wallet_file.write_text(json.dumps(stored), encoding="utf-8")

        with self.assertRaisesRegex(WalletError, "version 3 is required"):
            get_new_address("old_format", wallet_file=self.wallet_file)
        with self.assertRaisesRegex(WalletError, "version 3 is required"):
            rebuild_address_book("old_format", wallet_file=self.wallet_file)
        with self.assertRaisesRegex(WalletError, "version 3 is required"):
            get_wallet_address_book("old_format", wallet_file=self.wallet_file)
        with self.assertRaisesRegex(WalletError, "version 3 is required"):
            get_mnemonic("old_format", "correct", self.wallet_file)
        with self.assertRaisesRegex(WalletError, "version 3 is required"):
            export_account_xpub("old_format", "correct", self.wallet_file)
        with self.assertRaisesRegex(WalletError, "version 3 is required"):
            get_wallet_signing_key(
                "old_format",
                "m/84'/0'/0'/0/0",
                "correct",
                self.wallet_file,
            )

    def test_outdated_address_entry_is_rejected_not_migrated(self):
        create_wallet("outdated_entry", entropy_hex=ZERO_ENTROPY, wallet_file=self.wallet_file)
        get_new_address("outdated_entry", wallet_file=self.wallet_file)
        stored = json.loads(self.wallet_file.read_text(encoding="utf-8"))
        account = stored["outdated_entry"]["accounts"]["bip84-account-0"]
        account["issued_addresses"][0].pop("script_pubkey")
        self.wallet_file.write_text(json.dumps(stored), encoding="utf-8")

        with self.assertRaisesRegex(WalletError, "wallet address book is invalid"):
            get_wallet_address_book("outdated_entry", wallet_file=self.wallet_file)

        unchanged = json.loads(self.wallet_file.read_text(encoding="utf-8"))
        self.assertNotIn(
            "script_pubkey",
            unchanged["outdated_entry"]["accounts"]["bip84-account-0"]["issued_addresses"][0],
        )

    def test_data_directory_precedence(self):
        environment_dir = Path(self.temp_dir.name) / "environment"
        explicit_dir = Path(self.temp_dir.name) / "explicit"
        with patch.dict(os.environ, {"BITCOIN_TOOL_DATADIR": str(environment_dir)}):
            self.assertEqual(default_wallet_file(), environment_dir / "wallets.json")
            self.assertEqual(
                default_wallet_file(explicit_dir),
                explicit_dir / "wallets.json",
            )
            self.assertEqual(
                default_wallet_file(explicit_dir, NETWORK_TESTNET4),
                explicit_dir / "wallets_testnet4.json",
            )


if __name__ == "__main__":
    unittest.main()
