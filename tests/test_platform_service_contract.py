"""Failure-injection tests for the frozen wallet Platform boundary."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import wallet.service as platform_service_module
from wallet.service import (
    WalletCacheWarning,
    WalletImportCleanupError,
    WalletImportError,
    WalletService,
)
from wallet.wallet import (
    WalletError,
    get_wallet_address_book,
    mnemonic_from_entropy_hex,
)
from wallet.wallet_cache import CACHE_VERSION, save_wallet_cache


VALID_MNEMONIC = mnemonic_from_entropy_hex("00" * 32)


class EmptyBackend:
    network = "mainnet"
    base_url = "https://example.invalid/api"

    def verify_network(self):
        return None

    def get_tip_height(self):
        return 100

    def get_tip_hash(self):
        return "aa" * 32

    def get_address(self, address):
        return {
            "address": address,
            "chain_stats": {"tx_count": 0},
            "mempool_stats": {"tx_count": 0},
        }

    def get_address_utxos(self, address):
        return []

    def get_all_address_transactions(self, address):
        return []


class DiscoveryFailureBackend(EmptyBackend):
    def get_address(self, address):
        raise OSError("discovery backend offline")


class SyncFailureBackend(EmptyBackend):
    def get_tip_height(self):
        raise OSError("initial synchronization failed")


def cache_entry(name: str, confirmed: int = 0) -> dict:
    return {
        "wallet_name": name,
        "balance": {"confirmed": confirmed, "unconfirmed": 0},
        "addresses": [],
        "utxos": [],
        "transactions": [],
        "pending_transactions": [],
        "reserved_outpoints": {},
    }


class PlatformServiceContractTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        directory = Path(self.temporary.name)
        self.wallet_file = directory / "wallets.json"
        self.cache_file = directory / "wallet_cache.json"

    def tearDown(self):
        self.temporary.cleanup()

    def service(self, backend=None) -> WalletService:
        selected_backend = backend or EmptyBackend()
        return WalletService(
            self.wallet_file,
            self.cache_file,
            backend_factory=lambda _network: selected_backend,
        )

    def read_wallet_names(self) -> set[str]:
        if not self.wallet_file.exists():
            return set()
        return set(json.loads(self.wallet_file.read_text(encoding="utf-8")))

    def read_cache_names(self) -> set[str]:
        if not self.cache_file.exists():
            return set()
        cache = json.loads(self.cache_file.read_text(encoding="utf-8"))
        return set(cache["wallets"])

    def write_cache(self, entries: dict[str, dict]) -> None:
        save_wallet_cache(
            {"version": CACHE_VERSION, "wallets": entries},
            self.cache_file,
        )

    def authoritative_cache_entry(self, name: str, confirmed: int = 0) -> dict:
        entry = cache_entry(name, confirmed)
        entry["addresses"] = get_wallet_address_book(
            name,
            wallet_file=self.wallet_file,
        )["addresses"]
        return entry

    def test_create_returns_generated_words_but_import_does_not(self):
        created = self.service().create_wallet("created", "password")
        self.assertIsInstance(created.generated_mnemonic, str)
        self.assertTrue(created.generated_mnemonic)

        imported_service = WalletService(
            self.wallet_file.parent / "imported-wallets.json",
            self.wallet_file.parent / "imported-cache.json",
            backend_factory=lambda _network: EmptyBackend(),
        )
        imported = imported_service.import_wallet(
            "imported",
            "password",
            created.generated_mnemonic,
        )
        self.assertIsNone(imported.generated_mnemonic)
        self.assertFalse(hasattr(imported, "mnemonic"))
        self.assertNotIn(created.generated_mnemonic, repr(imported))

    def test_invalid_mnemonic_does_not_create_persistent_data(self):
        with self.assertRaisesRegex(WalletError, "mnemonic is invalid"):
            self.service().import_wallet("invalid", "password", "not a mnemonic")

        self.assertFalse(self.wallet_file.exists())
        self.assertFalse(self.cache_file.exists())

    def test_name_conflict_does_not_modify_wallet_or_cache_data(self):
        service = self.service()
        service.create_wallet("existing", "password")
        self.write_cache({"existing": cache_entry("existing", 123)})
        wallet_before = self.wallet_file.read_bytes()
        cache_before = self.cache_file.read_bytes()

        with self.assertRaisesRegex(WalletError, "already exists"):
            service.import_wallet("existing", "other-password", VALID_MNEMONIC)

        self.assertEqual(self.wallet_file.read_bytes(), wallet_before)
        self.assertEqual(self.cache_file.read_bytes(), cache_before)

    def test_discovery_failure_rolls_back_wallet_and_cache(self):
        service = self.service(DiscoveryFailureBackend())
        with self.assertRaises(WalletImportError) as raised:
            service.import_wallet("discovery-failure", "password", VALID_MNEMONIC)

        self.assertNotIn(VALID_MNEMONIC, str(raised.exception))
        self.assertNotIn("discovery-failure", self.read_wallet_names())
        self.assertNotIn("discovery-failure", self.read_cache_names())
        self.assertEqual(service.list_wallets(), ())

    def test_import_error_redacts_recovery_words_echoed_by_a_dependency(self):
        service = self.service()
        leaked_error = WalletError(f"dependency echoed {VALID_MNEMONIC}")

        with patch.object(
            service,
            "_discover_imported_wallet",
            side_effect=leaked_error,
        ):
            with self.assertRaises(WalletImportError) as raised:
                service.import_wallet("redacted", "password", VALID_MNEMONIC)

        self.assertNotIn(VALID_MNEMONIC, str(raised.exception))
        self.assertIn("[recovery words redacted]", str(raised.exception))
        self.assertTrue(raised.exception.__suppress_context__)
        self.assertNotIn("redacted", self.read_wallet_names())

    def test_initial_sync_failure_rolls_back_wallet_and_cache(self):
        service = self.service(SyncFailureBackend())
        with self.assertRaises(WalletImportError):
            service.import_wallet("sync-failure", "password", VALID_MNEMONIC)

        self.assertNotIn("sync-failure", self.read_wallet_names())
        self.assertNotIn("sync-failure", self.read_cache_names())
        self.assertEqual(service.list_wallets(), ())

    def test_failure_after_cache_write_rolls_back_both_stores(self):
        service = self.service()

        def fail_after_sync(_name):
            if self.cache_file.exists():
                raise WalletError("injected post-sync state failure")
            raise AssertionError("sync did not write its cache before state loading")

        with patch.object(service, "get_wallet_state", side_effect=fail_after_sync):
            with self.assertRaises(WalletImportError):
                service.import_wallet("post-sync-failure", "password", VALID_MNEMONIC)

        self.assertNotIn("post-sync-failure", self.read_wallet_names())
        self.assertNotIn("post-sync-failure", self.read_cache_names())

    def test_authoritative_cleanup_failure_is_explicit(self):
        service = self.service(DiscoveryFailureBackend())
        original_save = platform_service_module._save_wallets

        def fail_authoritative_cleanup(wallets, wallet_file):
            if "cleanup-failure" not in wallets:
                raise WalletError("injected authoritative cleanup failure")
            return original_save(wallets, wallet_file)

        with patch.object(
            platform_service_module,
            "_save_wallets",
            side_effect=fail_authoritative_cleanup,
        ):
            with self.assertRaisesRegex(
                WalletImportCleanupError,
                "cleanup may be incomplete.*authoritative wallet data",
            ):
                service.import_wallet("cleanup-failure", "password", VALID_MNEMONIC)

        self.assertIn("cleanup-failure", self.read_wallet_names())

    def test_cache_cleanup_failure_is_explicit(self):
        service = self.service(DiscoveryFailureBackend())
        with patch.object(
            service,
            "_remove_cache_entry",
            side_effect=WalletError("injected cache cleanup failure"),
        ):
            with self.assertRaisesRegex(
                WalletImportCleanupError,
                "cleanup may be incomplete.*wallet cache data",
            ):
                service.import_wallet("cache-cleanup", "password", VALID_MNEMONIC)

        self.assertNotIn("cache-cleanup", self.read_wallet_names())

    def test_stale_target_cache_does_not_block_or_override_rename(self):
        service = self.service()
        service.create_wallet("before", "password")
        self.write_cache(
            {
                "before": self.authoritative_cache_entry("before", 111),
                "after": cache_entry("after", 999),
            }
        )

        renamed = service.rename_wallet("before", "after", "password")

        self.assertEqual(renamed.metadata.name, "after")
        self.assertEqual(renamed.authoritative_balance_sats, 111)
        self.assertEqual(self.read_wallet_names(), {"after"})
        self.assertEqual(self.read_cache_names(), {"after"})

    def test_rename_cache_write_failure_keeps_authoritative_success(self):
        service = self.service()
        service.create_wallet("before", "password")
        self.write_cache(
            {"before": self.authoritative_cache_entry("before", 111)}
        )

        with patch.object(
            platform_service_module,
            "save_wallet_cache",
            side_effect=WalletError("injected cache write failure"),
        ):
            with self.assertWarns(WalletCacheWarning):
                renamed = service.rename_wallet("before", "after", "password")

        self.assertEqual(renamed.metadata.name, "after")
        self.assertTrue(self.cache_file.exists())
        restarted = self.service()
        self.assertEqual(
            [wallet.name for wallet in restarted.list_wallets()],
            ["after"],
        )
        self.assertEqual(restarted.get_wallet_state("after").balance_sats, 0)

    def test_invalid_migrated_cache_cannot_negate_authoritative_rename(self):
        service = self.service()
        service.create_wallet("before", "password")
        invalid_entry = self.authoritative_cache_entry("before", 111)
        invalid_entry["transactions"] = "not-a-list"
        self.write_cache({"before": invalid_entry})

        with self.assertWarns(WalletCacheWarning):
            renamed = service.rename_wallet("before", "after", "password")

        self.assertEqual(renamed.metadata.name, "after")
        self.assertEqual(renamed.balance_sats, 0)
        self.assertEqual(self.read_wallet_names(), {"after"})

    def test_remove_cache_write_failure_keeps_authoritative_success(self):
        service = self.service()
        service.create_wallet("remove-me", "password")
        self.write_cache(
            {"remove-me": self.authoritative_cache_entry("remove-me", 222)}
        )

        with patch.object(
            platform_service_module,
            "save_wallet_cache",
            side_effect=WalletError("injected cache write failure"),
        ):
            with self.assertWarns(WalletCacheWarning):
                service.remove_wallet("remove-me", "password")

        self.assertTrue(self.cache_file.exists())
        self.assertEqual(self.service().list_wallets(), ())

    def test_stale_cache_cannot_restore_a_removed_wallet(self):
        service = self.service()
        service.create_wallet("removed", "password")
        service.remove_wallet("removed", "password")
        self.write_cache({"removed": cache_entry("removed", 999)})

        restarted = self.service()
        self.assertEqual(restarted.list_wallets(), ())
        with self.assertRaisesRegex(WalletError, "does not exist"):
            restarted.get_wallet_state("removed")

    def test_sync_discards_payment_state_from_an_older_same_name_wallet(self):
        service = self.service()
        service.create_wallet("reused", "old-password")
        stale_entry = self.authoritative_cache_entry("reused", 999)
        stale_entry["reserved_outpoints"] = {
            ("aa" * 32) + ":0": {"draft_id": "old-draft"}
        }
        stale_entry["pending_transactions"] = [
            {
                "txid": "bb" * 32,
                "wallet_delta_sats": -100,
                "observed_in_sync": False,
            }
        ]
        self.write_cache({"reused": stale_entry})

        with patch.object(
            platform_service_module,
            "save_wallet_cache",
            side_effect=WalletError("injected cache write failure"),
        ):
            with self.assertWarns(WalletCacheWarning):
                service.remove_wallet("reused", "old-password")
            with self.assertWarns(WalletCacheWarning):
                service.create_wallet("reused", "new-password")

        state = service.sync_wallet("reused")
        refreshed = json.loads(self.cache_file.read_text(encoding="utf-8"))[
            "wallets"
        ]["reused"]

        self.assertEqual(state.balance_sats, 0)
        self.assertEqual(refreshed.get("reserved_outpoints", {}), {})
        self.assertEqual(refreshed.get("pending_transactions", []), [])

    def test_receive_address_selection_ignores_disposable_cache_flags(self):
        service = self.service()
        created = service.create_wallet("receive", "password")
        self.write_cache(
            {
                "receive": {
                    **cache_entry("receive"),
                    "addresses": [
                        {
                            "branch": 0,
                            "index": 0,
                            "address_type": "P2WPKH",
                            "used": True,
                        }
                    ],
                }
            }
        )

        self.assertEqual(
            service.get_receive_address("receive"),
            created.state.receive_address,
        )


if __name__ == "__main__":
    unittest.main()
