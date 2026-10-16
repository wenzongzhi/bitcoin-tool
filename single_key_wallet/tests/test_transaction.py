from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from decimal import Decimal
import json
from unittest.mock import patch

from network import EsploraError
from single_key_wallet import SingleKeyWalletError, SingleKeyTransactionError, SingleKeyWalletService
from single_key_wallet.codec import deserialize, serialize
from single_key_wallet.constants import SPEND_ADDRESS_TYPES
from single_key_wallet.models import TxOutput
from single_key_wallet.signing import verify_all_inputs
from single_key_wallet.scripts import destination_script
from single_key_wallet.storage import write_json
from single_key_wallet.tests.helpers import WalletFixture, FakeBackend, KEY_HEX, assert_no_secret_fields


class TransactionTest(WalletFixture):
    def test_ordinary_send_and_same_type_change_all_three_types(self):
        self.synchronize()
        for kind in SPEND_ADDRESS_TYPES:
            with self.subTest(kind=kind):
                document = self.prepare(kind, amount_sats=30_000, synchronize=False)
                self.assertEqual(document["input_count"], 1)
                self.assertEqual(document["outputs"][1]["address"], self.addresses[kind]["address"])
                self.assertEqual(document["outputs"][1]["script_pubkey"], self.addresses[kind]["script_pubkey"])
                self.assertTrue(document["outputs"][1]["is_change"])
                self.assertEqual(document["destination_amount_sats"], 30_000)
                self.assertGreaterEqual(Decimal(document["fee_rate_sat_vb"]), Decimal("2.5"))
                self.assertTrue(verify_all_inputs(deserialize(document["hex"]), document["inputs"]))
                assert_no_secret_fields(self, document)
                self.service.cancel_send("test", document["operation_id"])
                multi = self.prepare(kind, amount_sats=90_000, synchronize=False)
                self.assertEqual(multi["input_count"], 2)
                self.assertTrue(all(v["address_type"] == kind for v in multi["inputs"]))
                self.service.cancel_send("test", multi["operation_id"])

    def test_all_sweeps_one_source_only_and_fee_rate_changes_amount(self):
        self.synchronize()
        for kind in SPEND_ADDRESS_TYPES:
            document = self.prepare(kind, send_all=True, synchronize=False)
            self.assertEqual(document["input_count"], 2)
            self.assertEqual(len(document["outputs"]), 1)
            self.assertEqual(document["change_amount_sats"], 0)
            self.assertEqual(document["destination_amount_sats"], document["input_total_sats"] - document["fee_sats"])
            self.assertTrue(all(v["address_type"] == kind for v in document["inputs"]))
            self.service.cancel_send("test", document["operation_id"])
            expensive = self.service.prepare_send("test", kind, self.addresses["p2wpkh"]["address"], "5", send_all=True, password="password", synchronize=False)
            self.assertGreater(expensive["fee_sats"], document["fee_sats"])
            self.assertLess(expensive["destination_amount_sats"], document["destination_amount_sats"])
            self.service.cancel_send("test", expensive["operation_id"])

    def test_mainnet_and_testnet4_spending_equivalence(self):
        main = SingleKeyWalletService(self.directory / "main.json", self.directory / "main-cache.json")
        main.import_private_key_hex("main", KEY_HEX, "password")
        addresses = main.get_addresses("main")
        backend = FakeBackend("mainnet", addresses)
        main.backend_factory = lambda network: backend
        for kind in SPEND_ADDRESS_TYPES:
            document = main.prepare_send("main", kind, addresses["p2wpkh"]["address"], "2", send_all=True, password="password")
            self.assertTrue(verify_all_inputs(deserialize(document["hex"]), document["inputs"]))
            with self.assertRaisesRegex(SingleKeyTransactionError, "allow-mainnet"):
                main.broadcast(document)
            receipt = main.broadcast(document, allow_mainnet=True)
            self.assertEqual(receipt["txid"], document["txid"])

    def test_wrong_network_and_unsupported_source_types(self):
        self.synchronize()
        with self.assertRaisesRegex(SingleKeyTransactionError, "network"):
            self.service.prepare_send("test", "p2wpkh", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "2", send_all=True, password="password", synchronize=False)
        for kind in ("p2tr", "p2sh-p2wpkh"):
            with self.assertRaisesRegex(SingleKeyTransactionError, "not yet supported"):
                self.prepare(kind, send_all=True, synchronize=False)

    def test_signing_failure_releases_reservation(self):
        self.synchronize()
        with self.assertRaises(SingleKeyWalletError):
            self.service.prepare_send("test", "p2wpkh", self.addresses["p2wpkh"]["address"], "2", send_all=True, password="wrong", synchronize=False)
        cache = json.loads(self.cache_file.read_text())
        self.assertEqual(cache["wallets"]["test"]["reservations"], {})
        self.prepare(send_all=True, synchronize=False)

    def test_concurrent_send_cannot_select_same_utxos(self):
        self.synchronize()
        def attempt():
            try:
                return self.prepare(send_all=True, synchronize=False)
            except SingleKeyTransactionError:
                return None
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: attempt(), range(2)))
        self.assertEqual(sum(v is not None for v in results), 1)

    def test_successful_broadcast_prevents_reselection(self):
        document = self.prepare(send_all=True)
        self.service.broadcast(document)
        self.assertEqual(len(self.backend.broadcasts), 1)
        with self.assertRaises(SingleKeyTransactionError):
            self.prepare(send_all=True)
        cache = json.loads(self.cache_file.read_text())
        assert_no_secret_fields(self, cache)

    def test_failed_broadcast_preserves_signed_data_and_reservations(self):
        document = self.prepare(send_all=True)
        self.backend.fail_broadcast = True
        with self.assertRaises(EsploraError):
            self.service.broadcast(document)
        cache = json.loads(self.cache_file.read_text())["wallets"]["test"]
        pending = cache["pending_transactions"][document["txid"]]
        self.assertEqual(pending["status"], "broadcast_unknown")
        self.assertEqual(pending["signed_transaction"]["hex"], document["hex"])
        with self.assertRaisesRegex(SingleKeyTransactionError, "reconciled"):
            self.service.cancel_send("test", document["operation_id"])
        with self.assertRaises(SingleKeyTransactionError):
            self.prepare(send_all=True)

    def test_explicit_identical_retry_after_unknown_broadcast(self):
        document = self.prepare(send_all=True)
        self.backend.fail_broadcast = True
        with self.assertRaises(EsploraError):
            self.service.broadcast(document)
        self.backend.fail_broadcast = False
        self.assertEqual(self.service.broadcast(document)["txid"], document["txid"])
        self.assertEqual(len(self.backend.broadcasts), 2)
        self.assertEqual(self.backend.broadcasts[0], self.backend.broadcasts[1])

    def test_history_reconciles_uncertain_broadcast(self):
        document = self.prepare(send_all=True)
        self.backend.fail_broadcast = True
        with self.assertRaises(EsploraError):
            self.service.broadcast(document)
        address = self.addresses["p2wpkh"]["address"]
        observed = {
            "txid": document["txid"], "status": {"confirmed": False},
            "vin": [{"prevout": {"scriptpubkey_address": address, "value": v["value"]}} for v in document["inputs"]],
            "vout": [{"scriptpubkey_address": address, "value": document["destination_amount_sats"]}],
        }
        self.backend.history[address].append(observed)
        self.backend.utxos[address] = []
        self.synchronize()
        entry = json.loads(self.cache_file.read_text())["wallets"]["test"]
        self.assertEqual(entry["reservations"], {})
        self.assertEqual(entry["pending_spent_outpoints"], {})
        self.assertEqual(entry["pending_transactions"][document["txid"]]["status"], "mempool")

    def test_duplicate_key_names_share_outpoint_reservations(self):
        self.service.import_private_key_hex("same-key", KEY_HEX, "password")
        self.synchronize()
        self.service.sync_wallet("same-key")
        self.prepare(send_all=True, synchronize=False)
        with self.assertRaises(SingleKeyTransactionError):
            self.service.prepare_send("same-key", "p2wpkh", self.addresses["p2wpkh"]["address"], "2", send_all=True, password="password", synchronize=False)

    def test_dust_change_is_fee_and_no_output_for_every_source_type(self):
        self.backend = FakeBackend("testnet4", self.addresses, values=(10_250,))
        self.service.backend_factory = lambda network: self.backend
        self.synchronize()
        for kind in SPEND_ADDRESS_TYPES:
            dust = self.service.prepare_send("test", kind, self.addresses["p2wpkh"]["address"], "1", amount_sats=10_000, password="password", synchronize=False)
            self.assertEqual(len(dust["outputs"]), 1)
            self.assertEqual(dust["fee_sats"], 250)
            self.service.cancel_send("test", dust["operation_id"])

    def test_previous_transaction_value_tampering_is_detected(self):
        self.synchronize()
        cache = json.loads(self.cache_file.read_text())
        for item in cache["wallets"]["test"]["utxos"]:
            if item["address_type"] == "p2pkh-uncompressed":
                item["value"] += 10_000
        write_json(self.cache_file, cache)
        with patch("single_key_wallet.service.wallet_sync.sync_wallet"):
            with self.assertRaisesRegex(SingleKeyTransactionError, "cached prevout value"):
                self.service.prepare_send("test", "p2pkh-uncompressed", self.addresses["p2wpkh"]["address"], "2", send_all=True, password="password")

    def test_tampered_document_never_reaches_broadcast(self):
        document = self.prepare(send_all=True)
        for field in ("fee_sats", "input_total_sats", "destination_amount_sats"):
            altered = deepcopy(document)
            altered[field] += 1
            with self.assertRaises(SingleKeyTransactionError):
                self.service.broadcast(altered)
        altered = deepcopy(document)
        altered["max_fee_sats"] = document["fee_sats"] - 1
        with self.assertRaisesRegex(SingleKeyTransactionError, "final fee"):
            self.service.broadcast(altered)
        self.assertEqual(self.backend.broadcasts, [])

    def test_extra_output_metadata_cannot_enter_broadcast_cache(self):
        document = self.prepare(send_all=True)
        altered = deepcopy(document)
        altered["outputs"][0]["derivation_path"] = "not-an-HD-wallet"
        with self.assertRaises(SingleKeyTransactionError):
            self.service.broadcast(altered)
        self.assertEqual(self.backend.broadcasts, [])
        cache = json.loads(self.cache_file.read_text())["wallets"]["test"]
        self.assertEqual(cache.get("pending_transactions", {}), {})

    def test_mainnet_service_send_guard_precedes_funding(self):
        main = SingleKeyWalletService(self.directory / "main.json", self.directory / "main-cache.json")
        with patch.object(main, "prepare_send") as prepare:
            with self.assertRaisesRegex(SingleKeyTransactionError, "allow-mainnet"):
                main.send("main", "p2wpkh", "unused", "2", send_all=True, broadcast=True)
        prepare.assert_not_called()

    def test_final_fee_limit_releases_draft(self):
        self.synchronize()
        from single_key_wallet.signing import sign_transaction as original
        def larger_result(tx, prevouts, key):
            result = original(tx, prevouts, key)
            result["vsize"] = 1000
            return result
        with patch("single_key_wallet.transaction.sign_transaction", side_effect=larger_result):
            with self.assertRaisesRegex(SingleKeyTransactionError, r"^final fee 2500 sats exceeds max fee 1000 sats; transaction was not broadcast$"):
                self.prepare(send_all=True, max_fee_sats=1000, synchronize=False)
        self.assertEqual(json.loads(self.cache_file.read_text())["wallets"]["test"]["reservations"], {})
