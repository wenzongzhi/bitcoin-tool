import json
import tempfile
import unittest
from pathlib import Path

from wallet.wallet import create_wallet, get_new_address
from wallet.wallet_cache import CACHE_VERSION, save_wallet_cache, utc_now
from wallet.wallet_sync import sync_wallet


class EmptyBackend:
    network = "testnet4"
    base_url = "https://example.invalid/api"

    def verify_network(self):
        pass

    def get_tip_height(self):
        return 100

    def get_tip_hash(self):
        return "aa" * 32

    def get_address(self, address):
        return {"chain_stats": {}, "mempool_stats": {}}

    def get_address_utxos(self, address):
        return []

    def get_address_transactions(self, address):
        return []

    def get_all_address_transactions(self, address):
        return self.get_address_transactions(address)


class ObservedOutgoingBackend(EmptyBackend):
    def __init__(self, owned_address, confirmed):
        self.owned_address = owned_address
        self.confirmed = confirmed

    def get_address(self, address):
        return {
            "chain_stats": {"tx_count": int(self.confirmed)},
            "mempool_stats": {"tx_count": int(not self.confirmed)},
        }

    def get_address_utxos(self, address):
        if address != self.owned_address:
            return []
        return [
            {
                "txid": "33" * 32,
                "vout": 1,
                "value": 74_000,
                "status": {
                    "confirmed": self.confirmed,
                    **({"block_height": 100} if self.confirmed else {}),
                },
            }
        ]

    def get_all_address_transactions(self, address):
        if address != self.owned_address:
            return []
        return [
            {
                "txid": "33" * 32,
                "fee": 1_000,
                "status": {
                    "confirmed": self.confirmed,
                    **({"block_height": 100} if self.confirmed else {}),
                },
                "vin": [
                    {
                        "prevout": {
                            "scriptpubkey_address": self.owned_address,
                            "value": 100_000,
                        }
                    }
                ],
                "vout": [
                    {"scriptpubkey_address": "external", "value": 25_000},
                    {"scriptpubkey_address": self.owned_address, "value": 74_000},
                ],
            }
        ]


class TransactionCacheStateTest(unittest.TestCase):
    def test_sync_preserves_draft_reservations_and_unconfirmed_pending_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            wallet_file = directory / "wallets_testnet4.json"
            cache_file = directory / "wallet_cache_testnet4.json"
            create_wallet(
                "wallet",
                entropy_hex="00" * 32,
                wallet_file=wallet_file,
                network="testnet4",
            )
            get_new_address("wallet", wallet_file=wallet_file, network="testnet4")
            reservation = {
                "11" * 32 + ":0": {
                    "draft_id": "22" * 16,
                    "reserved_at": utc_now(),
                }
            }
            reserved_change = {
                "draft_id": "22" * 16,
                "address_type": "P2WPKH",
                "index": 0,
                "reserved_at": utc_now(),
            }
            pending = [{"txid": "33" * 32, "status": "broadcast"}]
            save_wallet_cache(
                {
                    "version": CACHE_VERSION,
                    "wallets": {
                        "wallet": {
                            "wallet_name": "wallet",
                            "synced_at": utc_now(),
                            "reserved_outpoints": reservation,
                            "reserved_change": reserved_change,
                            "pending_transactions": pending,
                        }
                    },
                },
                cache_file,
            )
            sync_wallet(
                "wallet",
                wallet_file=wallet_file,
                cache_file=cache_file,
                backend=EmptyBackend(),
                network="testnet4",
            )
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
            wallet_cache = cache["wallets"]["wallet"]
            self.assertEqual(wallet_cache["reserved_outpoints"], reservation)
            self.assertEqual(wallet_cache["reserved_change"], reserved_change)
            self.assertNotIn("active_payment_draft", wallet_cache)
            self.assertNotIn("change_address_reservations", wallet_cache)
            self.assertEqual(
                wallet_cache["pending_transactions"],
                [{**pending[0], "observed_in_sync": False}],
            )

    def test_pending_delta_reconciles_when_seen_and_later_confirmed(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            wallet_file = directory / "wallets_testnet4.json"
            cache_file = directory / "wallet_cache_testnet4.json"
            create_wallet(
                "wallet",
                entropy_hex="00" * 32,
                wallet_file=wallet_file,
                network="testnet4",
            )
            owned = get_new_address(
                "wallet", wallet_file=wallet_file, network="testnet4"
            )["address"]
            save_wallet_cache(
                {
                    "version": CACHE_VERSION,
                    "wallets": {
                        "wallet": {
                            "wallet_name": "wallet",
                            "synced_at": utc_now(),
                            "balance": {"confirmed": 100_000, "unconfirmed": 0},
                            "utxos": [],
                            "transactions": [
                                {
                                    "txid": "33" * 32,
                                    "direction": "send",
                                    "received": 74_000,
                                    "sent": 100_000,
                                    "net": -26_000,
                                    "fee": 1_000,
                                    "status": {"confirmed": False},
                                    "confirmed": False,
                                    "confirmations": 0,
                                    "addresses": [owned],
                                    "account_ids": ["bip84-account-0"],
                                    "address_types": ["P2WPKH"],
                                }
                            ],
                            "pending_transactions": [
                                {
                                    "txid": "33" * 32,
                                    "status": "broadcast",
                                    "wallet_delta_sats": -26_000,
                                    "observed_in_sync": False,
                                }
                            ],
                        }
                    },
                },
                cache_file,
            )

            mempool = sync_wallet(
                "wallet",
                wallet_file=wallet_file,
                cache_file=cache_file,
                backend=ObservedOutgoingBackend(owned, False),
                network="testnet4",
            )
            self.assertEqual(mempool["balance"]["pending_delta"], 0)
            self.assertEqual(mempool["balance"]["effective"], 74_000)
            self.assertTrue(
                mempool["pending_transactions"][0]["observed_in_sync"]
            )

            confirmed = sync_wallet(
                "wallet",
                wallet_file=wallet_file,
                cache_file=cache_file,
                backend=ObservedOutgoingBackend(owned, True),
                network="testnet4",
            )
            self.assertEqual(confirmed["balance"]["effective"], 74_000)
            self.assertEqual(confirmed["pending_transactions"], [])
            self.assertEqual(len(confirmed["transactions"]), 1)


if __name__ == "__main__":
    unittest.main()
