import json
import tempfile
import unittest
from pathlib import Path

from wallet.service import WalletService
from wallet.wallet import (
    WalletError,
    create_wallet,
    derive_wallet_address_candidate,
)


class AddressStatsBackend:
    """Backend double exposing only address-level discovery data."""

    network = "mainnet"

    def __init__(
        self,
        *,
        confirmed_addresses=(),
        mempool_addresses=(),
        failure_address=None,
    ):
        self.confirmed_addresses = set(confirmed_addresses)
        self.mempool_addresses = set(mempool_addresses)
        self.failure_address = failure_address
        self.queried = []

    def get_address(self, address):
        self.queried.append(address)
        if address == self.failure_address:
            raise RuntimeError("backend offline")
        return {
            "address": address,
            "chain_stats": {
                "tx_count": int(address in self.confirmed_addresses),
            },
            "mempool_stats": {
                "tx_count": int(address in self.mempool_addresses),
            },
        }


class WalletDiscoveryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        directory = Path(self.temporary.name)
        self.wallet_file = directory / "wallets.json"
        self.cache_file = directory / "wallet_cache.json"
        create_wallet(
            "wallet",
            entropy_hex="00" * 32,
            wallet_file=self.wallet_file,
        )

    def tearDown(self):
        self.temporary.cleanup()

    def _addresses(self, branch, through_index):
        return {
            index: derive_wallet_address_candidate(
                "wallet",
                index,
                wallet_file=self.wallet_file,
                change=branch == 1,
            )["address"]
            for index in range(through_index + 1)
        }

    def _discover(
        self,
        *,
        receive_confirmed=(),
        receive_mempool=(),
        change_confirmed=(),
        change_mempool=(),
        discovery_max_addresses=10_000,
    ):
        receive_indexes = {*receive_confirmed, *receive_mempool}
        change_indexes = {*change_confirmed, *change_mempool}
        receive = self._addresses(0, max(receive_indexes, default=0))
        change = self._addresses(1, max(change_indexes, default=0))
        backend = AddressStatsBackend(
            confirmed_addresses={receive[index] for index in receive_confirmed}
            | {change[index] for index in change_confirmed},
            mempool_addresses={receive[index] for index in receive_mempool}
            | {change[index] for index in change_mempool},
        )
        service = WalletService(
            self.wallet_file,
            self.cache_file,
            backend_factory=lambda _network: backend,
            discovery_max_addresses=discovery_max_addresses,
        )
        return service._discover_imported_wallet("wallet"), backend

    def test_finds_historical_use_at_required_indexes(self):
        cases = {
            0: {0},
            19: {19},
            20: {19, 20},
            25: {19, 25},
            50: {19, 39, 50},
        }
        for target, used in cases.items():
            with self.subTest(target=target):
                self.tearDown()
                self.setUp()
                result, _ = self._discover(receive_confirmed=used)
                self.assertIn(target, result.receive.used_indexes)
                self.assertEqual(result.receive.scanned_count, target + 21)

    def test_chain_and_mempool_transaction_counts_both_mark_address_used(self):
        result, _ = self._discover(
            receive_confirmed={0},
            change_mempool={0},
        )
        self.assertEqual(result.receive.used_indexes, (0,))
        self.assertEqual(result.change.used_indexes, (0,))

    def test_exactly_twenty_unused_addresses_finishes_at_gap_limit(self):
        result, backend = self._discover()
        self.assertEqual(result.receive.scanned_count, 20)
        self.assertEqual(result.change.scanned_count, 20)
        self.assertEqual(result.receive.used_indexes, ())
        self.assertEqual(len(backend.queried), 40)

        stored = json.loads(self.wallet_file.read_text(encoding="utf-8"))["wallet"]
        account = stored["accounts"]["bip84-account-0"]
        self.assertEqual(account["next_receive_index"], 1)
        self.assertEqual(account["next_change_index"], 0)
        self.assertEqual(len(account["issued_addresses"]), 1)
        self.assertEqual(account["issued_addresses"][0]["branch"], 0)
        self.assertEqual(account["issued_addresses"][0]["index"], 0)
        self.assertIsNotNone(account["issued_addresses"][0]["created_at"])

    def test_persists_only_history_through_last_used_and_next_receive(self):
        result, _ = self._discover(
            receive_confirmed={0},
            change_mempool={19, 25},
        )
        self.assertEqual(result.receive.used_indexes, (0,))
        self.assertEqual(result.change.used_indexes, (19, 25))

        stored = json.loads(self.wallet_file.read_text(encoding="utf-8"))["wallet"]
        account = stored["accounts"]["bip84-account-0"]
        receive_entries = [
            entry for entry in account["issued_addresses"] if entry["branch"] == 0
        ]
        change_entries = [
            entry for entry in account["issued_addresses"] if entry["branch"] == 1
        ]
        self.assertEqual([entry["index"] for entry in receive_entries], [0, 1])
        self.assertEqual([entry["index"] for entry in change_entries], list(range(26)))
        self.assertTrue(receive_entries[0]["used"])
        self.assertIsNone(receive_entries[0]["created_at"])
        self.assertFalse(receive_entries[1]["used"])
        self.assertIsNotNone(receive_entries[1]["created_at"])
        self.assertEqual(account["next_receive_index"], 2)
        self.assertEqual(account["next_change_index"], 26)

    def test_safety_limit_is_explicit_incomplete_discovery_error(self):
        address = self._addresses(0, 19)[19]
        backend = AddressStatsBackend(confirmed_addresses={address})
        service = WalletService(
            self.wallet_file,
            self.cache_file,
            backend_factory=lambda _network: backend,
            discovery_max_addresses=20,
        )
        with self.assertRaisesRegex(WalletError, "incomplete.*safety limit"):
            service._discover_imported_wallet("wallet")

        account = json.loads(self.wallet_file.read_text(encoding="utf-8"))[
            "wallet"
        ]["accounts"]["bip84-account-0"]
        self.assertEqual(account["issued_addresses"], [])
        self.assertEqual(account["next_receive_index"], 0)

    def test_backend_failure_does_not_persist_partial_discovery(self):
        failure_address = self._addresses(0, 3)[3]
        backend = AddressStatsBackend(failure_address=failure_address)
        service = WalletService(
            self.wallet_file,
            self.cache_file,
            backend_factory=lambda _network: backend,
        )
        with self.assertRaisesRegex(WalletError, "branch 0 index 3.*offline"):
            service._discover_imported_wallet("wallet")

        account = json.loads(self.wallet_file.read_text(encoding="utf-8"))[
            "wallet"
        ]["accounts"]["bip84-account-0"]
        self.assertEqual(account["issued_addresses"], [])
        self.assertEqual(account["next_receive_index"], 0)

    def test_rejects_invalid_discovery_safety_limits(self):
        for limit in (True, 0, -1, 19, 20.0, "20", None):
            with self.subTest(limit=limit):
                with self.assertRaisesRegex(WalletError, "safety limit"):
                    WalletService(
                        self.wallet_file,
                        self.cache_file,
                        discovery_max_addresses=limit,
                    )

    def test_rejects_malformed_address_statistics(self):
        class MalformedBackend(AddressStatsBackend):
            def get_address(self, address):
                return {
                    "chain_stats": {"tx_count": True},
                    "mempool_stats": {"tx_count": 0},
                }

        backend = MalformedBackend()
        service = WalletService(
            self.wallet_file,
            self.cache_file,
            backend_factory=lambda _network: backend,
        )
        with self.assertRaisesRegex(WalletError, "chain_stats.tx_count"):
            service._discover_imported_wallet("wallet")


if __name__ == "__main__":
    unittest.main()
