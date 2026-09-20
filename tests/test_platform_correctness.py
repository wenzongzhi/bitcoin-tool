import tempfile
import unittest
from pathlib import Path

from wallet.service import WalletService
from wallet.wallet import mnemonic_from_entropy_hex


class EmptyPlatformBackend:
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


class PlatformCorrectnessTest(unittest.TestCase):
    def test_import_uses_gap_discovery_and_exposes_explicit_balances(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            service = WalletService(
                directory / "wallets.json",
                directory / "wallet_cache.json",
                backend_factory=lambda _network: EmptyPlatformBackend(),
            )
            creation = service.import_wallet(
                "restored",
                None,
                mnemonic_from_entropy_hex("00" * 32),
            )

            self.assertEqual(creation.discovery.receive.scanned_count, 20)
            self.assertEqual(creation.discovery.change.scanned_count, 20)
            self.assertEqual(creation.state.authoritative_balance_sats, 0)
            self.assertEqual(creation.state.pending_delta_sats, 0)
            self.assertEqual(creation.state.effective_balance_sats, 0)
            self.assertEqual(creation.state.available_balance_sats, 0)
            self.assertEqual(creation.state.balance_sats, 0)


if __name__ == "__main__":
    unittest.main()
