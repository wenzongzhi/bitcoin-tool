import json
import tempfile
import unittest
from pathlib import Path

from btc.chainparams import NETWORK_MAINNET, NETWORK_TESTNET4
from wallet.wallet import WalletError, create_wallet, get_new_address
from wallet.wallet_cache import default_wallet_cache_file
from wallet.wallet_sync import (
    get_cached_balance,
    list_cached_transactions,
    list_cached_unspent,
    sync_wallet,
)


ZERO_ENTROPY = "00" * 32
TXID_1 = "11" * 32
TXID_2 = "22" * 32


class FakeEsploraBackend:
    base_url = "https://example.invalid/api"

    def __init__(self, funded_address, network=NETWORK_MAINNET):
        self.funded_address = funded_address
        self.network = network
        self.network_verified = False

    def get_tip_height(self):
        return 100

    def verify_network(self):
        self.network_verified = True

    def get_tip_hash(self):
        return "aa" * 32

    def get_address(self, address):
        if address != self.funded_address:
            return {
                "address": address,
                "chain_stats": {
                    "tx_count": 0,
                    "funded_txo_count": 0,
                    "funded_txo_sum": 0,
                    "spent_txo_count": 0,
                    "spent_txo_sum": 0,
                },
                "mempool_stats": {
                    "tx_count": 0,
                    "funded_txo_count": 0,
                    "funded_txo_sum": 0,
                    "spent_txo_count": 0,
                    "spent_txo_sum": 0,
                },
            }
        return {
            "address": address,
            "chain_stats": {
                "tx_count": 1,
                "funded_txo_count": 1,
                "funded_txo_sum": 50_000,
                "spent_txo_count": 0,
                "spent_txo_sum": 0,
            },
            "mempool_stats": {
                "tx_count": 1,
                "funded_txo_count": 1,
                "funded_txo_sum": 10_000,
                "spent_txo_count": 0,
                "spent_txo_sum": 0,
            },
        }

    def get_address_utxos(self, address):
        if address != self.funded_address:
            return []
        return [
            {
                "txid": TXID_1,
                "vout": 0,
                "value": 50_000,
                "status": {
                    "confirmed": True,
                    "block_height": 91,
                    "block_hash": "bb" * 32,
                },
            },
            {
                "txid": TXID_2,
                "vout": 1,
                "value": 10_000,
                "status": {"confirmed": False},
            },
        ]

    def get_address_transactions(self, address):
        if address != self.funded_address:
            return []
        return [
            {
                "txid": TXID_1,
                "fee": 100,
                "status": {
                    "confirmed": True,
                    "block_height": 91,
                    "block_hash": "bb" * 32,
                },
                "vin": [],
                "vout": [
                    {
                        "scriptpubkey_address": address,
                        "value": 50_000,
                    }
                ],
            },
            {
                "txid": TXID_2,
                "fee": 0,
                "status": {"confirmed": False},
                "vin": [],
                "vout": [
                    {
                        "scriptpubkey_address": address,
                        "value": 10_000,
                    }
                ],
            },
        ]

    def get_all_address_transactions(self, address):
        return self.get_address_transactions(address)


class WalletSyncTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temp_dir.name)
        self.wallet_file = self.data_dir / "wallets.json"
        self.cache_file = default_wallet_cache_file(self.data_dir)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sync_wallet_writes_cache_and_marks_used_addresses(self):
        create_wallet("sync_test", entropy_hex=ZERO_ENTROPY, wallet_file=self.wallet_file)
        first = get_new_address("sync_test", wallet_file=self.wallet_file)
        second = get_new_address("sync_test", wallet_file=self.wallet_file)
        legacy = get_new_address(
            "sync_test",
            wallet_file=self.wallet_file,
            address_type="p2pkh",
        )

        backend = FakeEsploraBackend(first["address"])
        result = sync_wallet(
            "sync_test",
            wallet_file=self.wallet_file,
            cache_file=self.cache_file,
            backend=backend,
        )

        self.assertTrue(backend.network_verified)
        self.assertEqual(result["address_count"], 3)
        self.assertEqual(result["used_address_count"], 1)
        self.assertEqual(result["balance"]["confirmed"], 50_000)
        self.assertEqual(result["balance"]["unconfirmed"], 10_000)
        self.assertEqual(result["balance"]["total"], 60_000)
        self.assertEqual(len(result["utxos"]), 2)
        self.assertEqual(len(result["transactions"]), 2)
        self.assertTrue(result["transactions_complete"])
        self.assertEqual(result["balance"]["effective"], 60_000)
        self.assertEqual(result["balance"]["available"], 50_000)
        self.assertTrue(self.cache_file.exists())

        stored_wallet = json.loads(self.wallet_file.read_text(encoding="utf-8"))["sync_test"]
        issued = stored_wallet["accounts"]["bip84-account-0"]["issued_addresses"]
        legacy_issued = stored_wallet["accounts"]["bip44-account-0"]["issued_addresses"]
        self.assertEqual(issued[0]["address"], first["address"])
        self.assertTrue(issued[0]["used"])
        self.assertFalse(issued[1]["used"])
        self.assertEqual(len(issued[0]["script_pubkey"]), 44)
        self.assertEqual(issued[1]["address"], second["address"])
        self.assertEqual(legacy_issued[0]["address"], legacy["address"])
        self.assertFalse(legacy_issued[0]["used"])

        balance = get_cached_balance("sync_test", self.cache_file)
        self.assertEqual(balance["balance"]["total"], 60_000)

        unspent = list_cached_unspent("sync_test", self.cache_file)
        self.assertEqual([utxo["value"] for utxo in unspent["utxos"]], [50_000, 10_000])
        self.assertEqual(unspent["utxos"][0]["confirmations"], 10)
        self.assertEqual(unspent["utxos"][0]["account_id"], "bip84-account-0")
        self.assertEqual(unspent["utxos"][0]["address_type"], "P2WPKH")

        transactions = list_cached_transactions("sync_test", self.cache_file)
        self.assertEqual({tx["txid"] for tx in transactions["transactions"]}, {TXID_1, TXID_2})
        self.assertTrue(
            all(
                tx["account_ids"] == ["bip84-account-0"]
                and tx["address_types"] == ["P2WPKH"]
                for tx in transactions["transactions"]
            )
        )

    def test_version_1_cache_is_rejected_without_migration(self):
        self.cache_file.write_text(
            json.dumps({"version": 1, "wallets": {}}),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(WalletError, "invalid wallet cache file"):
            get_cached_balance("sync_test", self.cache_file)

    def test_testnet4_cache_uses_separate_filename(self):
        self.assertEqual(
            default_wallet_cache_file(self.data_dir, NETWORK_TESTNET4),
            self.data_dir / "wallet_cache_testnet4.json",
        )

    def test_testnet4_sync_uses_testnet_wallet_and_cache(self):
        wallet_file = self.data_dir / "wallets_testnet4.json"
        cache_file = default_wallet_cache_file(self.data_dir, NETWORK_TESTNET4)
        create_wallet(
            "testnet_sync",
            entropy_hex=ZERO_ENTROPY,
            wallet_file=wallet_file,
            network=NETWORK_TESTNET4,
        )
        issued = get_new_address(
            "testnet_sync",
            wallet_file=wallet_file,
            network=NETWORK_TESTNET4,
        )
        backend = FakeEsploraBackend(issued["address"], NETWORK_TESTNET4)

        result = sync_wallet(
            "testnet_sync",
            wallet_file=wallet_file,
            cache_file=cache_file,
            backend=backend,
            network=NETWORK_TESTNET4,
        )

        self.assertTrue(backend.network_verified)
        self.assertTrue(issued["address"].startswith("tb1q"))
        self.assertEqual(result["balance"]["total"], 60_000)
        self.assertTrue(cache_file.exists())
        self.assertFalse((self.data_dir / "wallet_cache.json").exists())

        with self.assertRaisesRegex(WalletError, "backend network"):
            sync_wallet(
                "testnet_sync",
                wallet_file=wallet_file,
                cache_file=cache_file,
                backend=FakeEsploraBackend(issued["address"]),
                network=NETWORK_TESTNET4,
            )


if __name__ == "__main__":
    unittest.main()
