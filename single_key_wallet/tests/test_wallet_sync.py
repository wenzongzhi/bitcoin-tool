from copy import deepcopy
import json

from single_key_wallet.tests.helpers import WalletFixture, assert_no_secret_fields


class SyncTest(WalletFixture):
    def test_all_five_addresses_balances_and_public_only_cache(self):
        result = self.service.sync_wallet("test")
        self.assertEqual(result["address_count"], 5)
        self.assertEqual(result["detected_balance_sats"], 600_000)
        self.assertEqual(result["spendable_balance_sats"], 360_000)
        for method in ("stats", "utxos", "history"):
            self.assertEqual({a for m, a in self.backend.queries if m == method}, {v["address"] for v in self.addresses.values()})
        self.assertEqual(self.service.get_balance("test")["detected_balance_sats"], 600_000)
        utxos = self.service.list_unspent("test")
        self.assertEqual(len(utxos), 10)
        self.assertEqual({v["address_type"] for v in utxos}, set(self.addresses))
        self.assertEqual(len(self.service.list_unspent("test", "p2tr")), 2)
        self.assertFalse(self.service.get_balance("test")["per_address_type"]["p2tr"]["spend_supported"])
        assert_no_secret_fields(self, json.loads(self.cache_file.read_text()))

    def test_history_deduplication_across_addresses(self):
        first, second = [v["address"] for v in self.addresses.values()][:2]
        transaction = deepcopy(self.backend.history[first][0])
        transaction["vout"].append({"scriptpubkey_address": second, "value": 12_345})
        self.backend.history[first][0] = transaction
        self.backend.history[second].append(deepcopy(transaction))
        self.synchronize()
        matches = [v for v in self.service.list_transactions("test") if v["txid"] == transaction["txid"]]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["received_sats"], 62_345)
        self.assertEqual(len(matches[0]["address_types"]), 2)

    def test_mempool_delta_does_not_double_count_confirmed_spends(self):
        address = self.addresses["p2wpkh"]["address"]
        self.backend.stats[address]["mempool_stats"]["spent_txo_sum"] = 70_000
        self.backend.stats[address]["mempool_stats"]["funded_txo_sum"] = 10_000
        self.synchronize()
        value = self.service.get_balance("test")["per_address_type"]["p2wpkh"]
        self.assertEqual(value["confirmed_balance_sats"], 120_000)
        self.assertEqual(value["unconfirmed_balance_sats"], -60_000)
        self.assertEqual(value["balance_sats"], 60_000)

    def test_failed_history_does_not_replace_cache(self):
        self.synchronize()
        before = self.cache_file.read_bytes()
        self.backend.fail_history = True
        with self.assertRaises(RuntimeError):
            self.synchronize()
        self.assertEqual(before, self.cache_file.read_bytes())
