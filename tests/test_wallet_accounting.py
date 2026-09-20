import unittest
from datetime import datetime, timedelta, timezone

from wallet.transaction_accounting import (
    calculate_wallet_balance,
    pending_summary_from_signed,
)


OWNED = {
    "source": {
        "address": "source",
        "account_id": "bip84-account-0",
        "address_type": "P2WPKH",
    },
    "change": {
        "address": "change",
        "account_id": "bip84-account-0",
        "address_type": "P2WPKH",
    },
    "self": {
        "address": "self",
        "account_id": "bip84-account-0",
        "address_type": "P2WPKH",
    },
}


def signed(outputs, *, fee=1_000):
    return {
        "txid": "11" * 32,
        "fee_sats": fee,
        "inputs": [{"address": "source", "value": 100_000}],
        "outputs": outputs,
    }


def confirmed_utxo(txid="22" * 32, value=100_000):
    return {
        "txid": txid,
        "vout": 0,
        "value": value,
        "confirmed": True,
    }


class WalletAccountingTest(unittest.TestCase):
    def test_pending_outgoing_with_change_includes_fee_once(self):
        summary = pending_summary_from_signed(
            signed(
                [
                    {"address": "external", "value": 25_000},
                    {"address": "change", "value": 74_000},
                ]
            ),
            OWNED,
        )
        self.assertEqual(summary["sent"], 100_000)
        self.assertEqual(summary["received"], 74_000)
        self.assertEqual(summary["net"], -26_000)
        self.assertEqual(summary["fee"], 1_000)

    def test_pending_outgoing_without_change_debits_the_full_input(self):
        summary = pending_summary_from_signed(
            signed([{"address": "external", "value": 99_000}]), OWNED
        )
        self.assertEqual(summary["received"], 0)
        self.assertEqual(summary["net"], -100_000)

    def test_self_transfer_is_identified_and_only_fee_reduces_balance(self):
        summary = pending_summary_from_signed(
            signed([{"address": "self", "value": 99_000}]), OWNED
        )
        self.assertEqual(summary["direction"], "self")
        self.assertEqual(summary["net"], -1_000)

    def test_unobserved_pending_delta_updates_effective_not_authoritative_balance(self):
        cache = {
            "balance": {"confirmed": 100_000, "unconfirmed": 0},
            "utxos": [confirmed_utxo()],
            "pending_transactions": [
                {
                    "txid": "11" * 32,
                    "wallet_delta_sats": -26_000,
                    "observed_in_sync": False,
                }
            ],
            "pending_spent_outpoints": {"22" * 32 + ":0": {}},
        }
        balance = calculate_wallet_balance(cache)
        self.assertEqual(balance.authoritative_sats, 100_000)
        self.assertEqual(balance.pending_delta_sats, -26_000)
        self.assertEqual(balance.effective_sats, 74_000)
        self.assertEqual(balance.available_sats, 0)

    def test_multiple_pending_transactions_survive_restart_cache_shape(self):
        cache = {
            "balance": {"confirmed": 200_000, "unconfirmed": 0},
            "utxos": [],
            "pending_transactions": [
                {"wallet_delta_sats": -26_000, "observed_in_sync": False},
                {"wallet_delta_sats": -11_000, "observed_in_sync": False},
            ],
        }
        self.assertEqual(calculate_wallet_balance(cache).effective_sats, 163_000)

    def test_backend_observation_and_confirmation_remove_optimistic_delta(self):
        observed = {
            "balance": {"confirmed": 0, "unconfirmed": 74_000},
            "utxos": [],
            "pending_transactions": [
                {"wallet_delta_sats": -26_000, "observed_in_sync": True}
            ],
        }
        confirmed = {
            "balance": {"confirmed": 74_000, "unconfirmed": 0},
            "utxos": [confirmed_utxo(value=74_000)],
            "pending_transactions": [],
        }
        self.assertEqual(calculate_wallet_balance(observed).effective_sats, 74_000)
        self.assertEqual(calculate_wallet_balance(confirmed).effective_sats, 74_000)

    def test_unconfirmed_incoming_is_effective_but_not_available(self):
        cache = {
            "balance": {"confirmed": 0, "unconfirmed": 50_000},
            "utxos": [
                {
                    "txid": "33" * 32,
                    "vout": 0,
                    "value": 50_000,
                    "confirmed": False,
                }
            ],
        }
        balance = calculate_wallet_balance(cache)
        self.assertEqual(balance.authoritative_sats, 50_000)
        self.assertEqual(balance.effective_sats, 50_000)
        self.assertEqual(balance.available_sats, 0)

    def test_available_balance_honors_reservations_until_explicit_transition(self):
        now = datetime.now(timezone.utc)
        outpoint = "22" * 32 + ":0"
        cache = {
            "balance": {"confirmed": 100_000, "unconfirmed": 0},
            "utxos": [confirmed_utxo()],
            "reserved_outpoints": {
                outpoint: {
                    "reserved_at": now.replace(microsecond=0).isoformat(),
                }
            },
        }
        self.assertEqual(calculate_wallet_balance(cache, now=now).available_sats, 0)
        cache["reserved_outpoints"][outpoint]["reserved_at"] = (
            now - timedelta(hours=2)
        ).isoformat()
        self.assertEqual(
            calculate_wallet_balance(cache, now=now).available_sats,
            0,
        )


if __name__ == "__main__":
    unittest.main()
