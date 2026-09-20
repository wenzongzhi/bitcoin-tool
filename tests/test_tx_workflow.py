import json
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tx.builder import create_raw_transaction
from tx.document import validate_signed_document
from tx.errors import TransactionError
from tx.workflow import (
    broadcast_signed_transaction,
    cancel_transaction_draft,
    fund_all_transaction,
    fund_transaction,
    release_transaction_draft,
    sign_funded_transaction,
)
from tx.verifier import verify_all_inputs
from wallet.wallet import create_wallet, get_new_address, get_wallet_address_book
from wallet.wallet_cache import CACHE_VERSION, save_wallet_cache, utc_now


ZERO_ENTROPY = "00" * 32


class FakeBroadcastBackend:
    def __init__(self, network, expected_txid):
        self.network = network
        self.expected_txid = expected_txid
        self.base_url = "https://example.invalid/api"
        self.network_verified = False

    def verify_network(self):
        self.network_verified = True

    def broadcast_transaction(self, raw_tx_hex):
        self.raw_tx_hex = raw_tx_hex
        return self.expected_txid


class FailingBroadcastBackend(FakeBroadcastBackend):
    def broadcast_transaction(self, raw_tx_hex):
        raise RuntimeError("backend unavailable")


class TransactionWorkflowTest(unittest.TestCase):
    def _fund_from_sendall_fixture(self, directory, amount=10_000):
        wallet_file, cache_file, wallet_name, destination = self._sendall_fixture(
            directory
        )
        template = create_raw_transaction(
            [], [{"address": destination, "amount_sats": amount}], "testnet4"
        )
        funded = fund_transaction(
            template,
            wallet_name,
            wallet_file,
            cache_file,
            "testnet4",
            "p2wpkh",
            2,
        )
        return wallet_file, cache_file, wallet_name, funded

    def _sendall_fixture(
        self,
        directory: Path,
        network: str = "testnet4",
        address_type: str = "p2wpkh",
    ) -> tuple[Path, Path, str, str]:
        wallet_file = directory / "wallets.json"
        cache_file = directory / "wallet_cache.json"
        wallet_name = "sendall_wallet"
        create_wallet(
            wallet_name,
            entropy_hex=ZERO_ENTROPY,
            wallet_file=wallet_file,
            network=network,
        )
        sources = [
            get_new_address(
                wallet_name,
                wallet_file=wallet_file,
                address_type=address_type,
                network=network,
            )
            for _ in range(2)
        ]
        destination = get_new_address(
            wallet_name,
            wallet_file=wallet_file,
            address_type=address_type,
            network=network,
        )
        entries = {
            item["path"]: item
            for item in get_wallet_address_book(
                wallet_name,
                wallet_file=wallet_file,
                address_type=address_type,
                network=network,
            )["addresses"]
        }
        utxos = []
        for offset, (source, value) in enumerate(zip(sources, (40_000, 60_000)), start=1):
            entry = entries[source["derivation_path"]]
            utxos.append(
                {
                    "txid": f"{offset:02x}" * 32,
                    "vout": 0,
                    "value": value,
                    "status": {"confirmed": True, "block_height": 1},
                    "confirmed": True,
                    "confirmations": 100,
                    "address": entry["address"],
                    "path": entry["path"],
                    "branch": entry["branch"],
                    "index": entry["index"],
                    "script_pubkey": entry["script_pubkey"],
                    "account_id": entry["account_id"],
                    "address_type": entry["address_type"],
                }
            )
        save_wallet_cache(
            {
                "version": CACHE_VERSION,
                "wallets": {
                    wallet_name: {
                        "wallet_name": wallet_name,
                        "synced_at": utc_now(),
                        "utxos": utxos,
                    }
                },
            },
            cache_file,
        )
        return wallet_file, cache_file, wallet_name, destination["address"]

    def _exercise(self, network: str, address_type: str):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            wallet_file = directory / "wallets.json"
            cache_file = directory / "wallet_cache.json"
            wallet_name = "test_wallet"
            create_wallet(
                wallet_name,
                entropy_hex=ZERO_ENTROPY,
                wallet_file=wallet_file,
                network=network,
            )
            source = get_new_address(
                wallet_name,
                wallet_file=wallet_file,
                address_type=address_type,
                network=network,
            )
            destination = get_new_address(
                wallet_name,
                wallet_file=wallet_file,
                address_type=address_type,
                network=network,
            )
            entry = next(
                item
                for item in get_wallet_address_book(
                    wallet_name,
                    wallet_file=wallet_file,
                    address_type=address_type,
                    network=network,
                )["addresses"]
                if item["path"] == source["derivation_path"]
            )
            txid = ("11" if address_type == "p2wpkh" else "22") * 32
            utxo = {
                "txid": txid,
                "vout": 0,
                "value": 100_000,
                "status": {"confirmed": True, "block_height": 1},
                "confirmed": True,
                "confirmations": 100,
                "address": entry["address"],
                "path": entry["path"],
                "branch": entry["branch"],
                "index": entry["index"],
                "script_pubkey": entry["script_pubkey"],
                "account_id": entry["account_id"],
                "address_type": entry["address_type"],
            }
            save_wallet_cache(
                {
                    "version": CACHE_VERSION,
                    "wallets": {
                        wallet_name: {
                            "wallet_name": wallet_name,
                            "synced_at": utc_now(),
                            "utxos": [utxo],
                        }
                    },
                },
                cache_file,
            )
            template = create_raw_transaction(
                [],
                [{"address": destination["address"], "amount_sats": 25_000}],
                network,
            )
            funded = fund_transaction(
                template,
                wallet_name,
                wallet_file,
                cache_file,
                network,
                address_type,
                "2.5",
                max_fee_sats=2_000,
            )
            self.assertEqual(funded["change_position"], 1)
            self.assertTrue(funded["outputs"][1]["is_change"])
            self.assertIn("/1/0", funded["outputs"][1]["derivation_path"])
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
            wallet_cache = cache["wallets"][wallet_name]
            reservation = wallet_cache["reserved_outpoints"][f"{txid}:0"]
            self.assertEqual(reservation["draft_id"], funded["draft_id"])
            self.assertEqual(
                wallet_cache["reserved_change"]["draft_id"],
                funded["draft_id"],
            )
            self.assertEqual(wallet_cache["reserved_change"]["index"], 0)
            account_id = (
                "bip44-account-0" if address_type == "p2pkh" else "bip84-account-0"
            )
            stored = json.loads(wallet_file.read_text(encoding="utf-8"))[wallet_name]
            self.assertEqual(stored["accounts"][account_id]["next_change_index"], 0)

            tampered = deepcopy(funded)
            tampered["outputs"][1]["account_id"] = "not-this-wallet-account"
            with self.assertRaisesRegex(TransactionError, "change output"):
                sign_funded_transaction(
                    tampered,
                    wallet_name,
                    None,
                    wallet_file,
                    cache_file,
                    network,
                )
            failed_cache = json.loads(cache_file.read_text(encoding="utf-8"))[
                "wallets"
            ][wallet_name]
            self.assertEqual(failed_cache["reserved_outpoints"], {})
            self.assertNotIn("reserved_change", failed_cache)

            funded = fund_transaction(
                template,
                wallet_name,
                wallet_file,
                cache_file,
                network,
                address_type,
                "2.5",
                max_fee_sats=2_000,
            )
            signed = sign_funded_transaction(
                funded,
                wallet_name,
                None,
                wallet_file,
                cache_file,
                network,
                max_fee_sats=2_000,
            )
            tx, prevouts = validate_signed_document(signed, network)
            self.assertTrue(all(item["valid"] for item in verify_all_inputs(tx, prevouts)))
            self.assertGreaterEqual(
                signed["fee_sats"],
                int(2.5 * signed["vsize"]),
            )
            if address_type == "p2wpkh":
                self.assertEqual(tx.inputs[0].script_sig, b"")
                self.assertEqual(len(tx.inputs[0].witness), 2)
            else:
                self.assertTrue(tx.inputs[0].script_sig)
                self.assertEqual(tx.inputs[0].witness, [])

            backend = FakeBroadcastBackend(network, signed["txid"])
            wrong_network = "mainnet" if network == "testnet4" else "testnet4"
            with self.assertRaisesRegex(TransactionError, "backend network"):
                broadcast_signed_transaction(
                    signed,
                    network,
                    FakeBroadcastBackend(wrong_network, signed["txid"]),
                    cache_file=cache_file,
                )
            broadcast = broadcast_signed_transaction(
                signed,
                network,
                backend,
                cache_file=cache_file,
            )
            self.assertTrue(backend.network_verified)
            self.assertEqual(broadcast["txid"], signed["txid"])
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
            wallet_cache = cache["wallets"][wallet_name]
            self.assertEqual(wallet_cache["reserved_outpoints"], {})
            self.assertEqual(
                wallet_cache["pending_spent_outpoints"][f"{txid}:0"]["spending_txid"],
                signed["txid"],
            )
            self.assertEqual(
                wallet_cache["pending_transactions"][0]["txid"],
                signed["txid"],
            )
            self.assertEqual(
                wallet_cache["pending_transactions"][0]["wallet_delta_sats"],
                -signed["fee_sats"],
            )
            self.assertEqual(
                wallet_cache["balance"]["effective"],
                100_000 - signed["fee_sats"],
            )
            self.assertEqual(wallet_cache["balance"]["available"], 0)

    def test_mainnet_and_testnet4_p2pkh_and_p2wpkh(self):
        for network in ("mainnet", "testnet4"):
            for address_type in ("p2pkh", "p2wpkh"):
                with self.subTest(network=network, address_type=address_type):
                    self._exercise(network, address_type)

    def test_sendall_spends_every_eligible_utxo_without_change(self):
        account_ids = {"p2pkh": "bip44-account-0", "p2wpkh": "bip84-account-0"}
        for network in ("mainnet", "testnet4"):
            for address_type in ("p2pkh", "p2wpkh"):
                with self.subTest(network=network, address_type=address_type):
                    with tempfile.TemporaryDirectory() as temporary:
                        directory = Path(temporary)
                        wallet_file, cache_file, wallet_name, destination = self._sendall_fixture(
                            directory,
                            network,
                            address_type,
                        )
                        funded = fund_all_transaction(
                            destination,
                            wallet_name,
                            cache_file,
                            network,
                            address_type,
                            "2",
                            max_fee_sats=1_000,
                        )
                        self.assertEqual(len(funded["inputs"]), 2)
                        self.assertEqual(len(funded["outputs"]), 1)
                        self.assertIsNone(funded["change_position"])
                        self.assertTrue(funded["send_all"])
                        self.assertEqual(funded["total_input_sats"], 100_000)
                        self.assertEqual(
                            funded["outputs"][0]["value"],
                            100_000 - funded["estimated_fee_sats"],
                        )

                        signed = sign_funded_transaction(
                            funded,
                            wallet_name,
                            None,
                            wallet_file,
                            cache_file,
                            network,
                            max_fee_sats=1_000,
                            final_fee_limit_message=True,
                        )
                        tx, prevouts = validate_signed_document(signed, network)
                        self.assertEqual(len(tx.inputs), 2)
                        self.assertEqual(len(tx.outputs), 1)
                        self.assertTrue(
                            all(item["valid"] for item in verify_all_inputs(tx, prevouts))
                        )
                        stored_wallet = json.loads(
                            wallet_file.read_text(encoding="utf-8")
                        )[wallet_name]
                        self.assertEqual(
                            stored_wallet["accounts"][account_ids[address_type]][
                                "next_change_index"
                            ],
                            0,
                        )

    def test_sendall_rejects_estimated_and_final_fee_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            wallet_file, cache_file, wallet_name, destination = self._sendall_fixture(directory)
            with self.assertRaisesRegex(
                TransactionError,
                r"^estimated fee 356 sats exceeds max fee 355 sats$",
            ):
                fund_all_transaction(
                    destination,
                    wallet_name,
                    cache_file,
                    "testnet4",
                    "p2wpkh",
                    "2",
                    max_fee_sats=355,
                )
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
            self.assertNotIn(
                "reserved_outpoints",
                cache["wallets"][wallet_name],
            )

            funded = fund_all_transaction(
                destination,
                wallet_name,
                cache_file,
                "testnet4",
                "p2wpkh",
                "2",
            )
            with self.assertRaisesRegex(
                TransactionError,
                r"^final fee 356 sats exceeds max fee 355 sats; transaction was not broadcast$",
            ):
                sign_funded_transaction(
                    funded,
                    wallet_name,
                    None,
                    wallet_file,
                    cache_file,
                    "testnet4",
                    max_fee_sats=355,
                    final_fee_limit_message=True,
                )
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
            self.assertEqual(
                cache["wallets"][wallet_name]["reserved_outpoints"],
                {},
            )

    def test_repeated_prepare_cancel_does_not_advance_change_index(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for _ in range(25):
                wallet_file, cache_file, wallet_name, funded = (
                    self._fund_from_sendall_fixture(directory)
                    if not (directory / "wallets.json").exists()
                    else self._fund_existing_fixture(directory)
                )
                self.assertTrue(funded["outputs"][1]["derivation_path"].endswith("/1/0"))
                release_transaction_draft(cache_file, wallet_name, funded["draft_id"])
            stored = json.loads(wallet_file.read_text(encoding="utf-8"))[wallet_name]
            self.assertEqual(
                stored["accounts"]["bip84-account-0"]["next_change_index"], 0
            )

    def _fund_existing_fixture(self, directory, amount=10_000):
        wallet_file = directory / "wallets.json"
        cache_file = directory / "wallet_cache.json"
        wallet_name = "sendall_wallet"
        address_book = get_wallet_address_book(
            wallet_name,
            wallet_file=wallet_file,
            address_type="p2wpkh",
            network="testnet4",
        )
        destination = next(
            item["address"] for item in address_book["addresses"] if item["branch"] == 0
        )
        template = create_raw_transaction(
            [], [{"address": destination, "amount_sats": amount}], "testnet4"
        )
        funded = fund_transaction(
            template,
            wallet_name,
            wallet_file,
            cache_file,
            "testnet4",
            "p2wpkh",
            2,
        )
        return wallet_file, cache_file, wallet_name, funded

    def test_wallet_rejects_a_second_active_draft(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            wallet_file, cache_file, wallet_name, first = self._fund_from_sendall_fixture(
                directory
            )
            with self.assertRaisesRegex(
                TransactionError,
                "already has an active payment draft",
            ):
                self._fund_existing_fixture(directory)
            self.assertTrue(first["outputs"][1]["derivation_path"].endswith("/1/0"))

            release_transaction_draft(cache_file, wallet_name, first["draft_id"])
            _, _, _, replacement = self._fund_existing_fixture(directory)
            self.assertTrue(
                replacement["outputs"][1]["derivation_path"].endswith("/1/0")
            )
            stored = json.loads(wallet_file.read_text(encoding="utf-8"))[wallet_name]
            self.assertEqual(
                stored["accounts"]["bip84-account-0"]["next_change_index"], 0
            )

    def test_successful_signing_issues_reserved_change_address(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            wallet_file, cache_file, wallet_name, funded = self._fund_from_sendall_fixture(
                directory
            )
            signed = sign_funded_transaction(
                funded,
                wallet_name,
                None,
                wallet_file,
                cache_file,
                "testnet4",
            )
            stored = json.loads(wallet_file.read_text(encoding="utf-8"))[wallet_name]
            account = stored["accounts"]["bip84-account-0"]
            self.assertEqual(account["next_change_index"], 1)
            issued = next(
                item
                for item in account["issued_addresses"]
                if item["branch"] == 1 and item["index"] == 0
            )
            self.assertFalse(issued["used"])
            self.assertIsNotNone(issued["created_at"])
            self.assertNotIn("lifecycle_state", issued)
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
            wallet_cache = cache["wallets"][wallet_name]
            self.assertNotIn("reserved_change", wallet_cache)
            self.assertTrue(wallet_cache["reserved_outpoints"])
            self.assertTrue(
                all(
                    reservation["draft_id"] == funded["draft_id"]
                    for reservation in wallet_cache["reserved_outpoints"].values()
                )
            )

            backend = FakeBroadcastBackend("testnet4", signed["txid"])
            broadcast_signed_transaction(
                signed,
                "testnet4",
                backend,
                cache_file=cache_file,
                wallet_file=wallet_file,
            )
            stored = json.loads(wallet_file.read_text(encoding="utf-8"))[wallet_name]
            account = stored["accounts"]["bip84-account-0"]
            self.assertEqual(account["next_change_index"], 1)
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
            self.assertEqual(
                cache["wallets"][wallet_name]["reserved_outpoints"],
                {},
            )
            self.assertNotIn("reserved_change", cache["wallets"][wallet_name])

    def test_reserved_draft_survives_restart_until_explicit_cancel(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            _, cache_file, _, first = self._fund_from_sendall_fixture(directory)
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
            reservation = cache["wallets"]["sendall_wallet"]["reserved_change"]
            reservation["reserved_at"] = (
                datetime.now(timezone.utc) - timedelta(hours=2)
            ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            save_wallet_cache(cache, cache_file)

            with self.assertRaisesRegex(
                TransactionError,
                "already has an active payment draft",
            ):
                self._fund_existing_fixture(directory)
            self.assertTrue(
                cancel_transaction_draft(cache_file, first["draft_id"])
            )
            _, _, _, replacement = self._fund_existing_fixture(directory)
            self.assertTrue(
                replacement["outputs"][1]["derivation_path"].endswith("/1/0")
            )

    def test_sendall_creates_no_change_reservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            _, cache_file, wallet_name, destination = self._sendall_fixture(directory)
            funded = fund_all_transaction(
                destination,
                wallet_name,
                cache_file,
                "testnet4",
                "p2wpkh",
                2,
            )
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
            wallet_cache = cache["wallets"][wallet_name]
            self.assertNotIn("reserved_change", wallet_cache)
            self.assertTrue(
                all(
                    reservation["draft_id"] == funded["draft_id"]
                    for reservation in wallet_cache["reserved_outpoints"].values()
                )
            )
            with self.assertRaisesRegex(
                TransactionError,
                "already has an active payment draft",
            ):
                fund_all_transaction(
                    destination,
                    wallet_name,
                    cache_file,
                    "testnet4",
                    "p2wpkh",
                    2,
                )

    def test_cancel_after_signing_keeps_change_issued(self):
        with tempfile.TemporaryDirectory() as temporary:
            wallet_file, cache_file, wallet_name, funded = (
                self._fund_from_sendall_fixture(Path(temporary))
            )
            sign_funded_transaction(
                funded,
                wallet_name,
                None,
                wallet_file,
                cache_file,
                "testnet4",
            )
            with self.assertRaisesRegex(
                TransactionError,
                "already has an active payment draft",
            ):
                self._fund_existing_fixture(Path(temporary))
            release_transaction_draft(cache_file, wallet_name, funded["draft_id"])
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
            wallet_cache = cache["wallets"][wallet_name]
            self.assertEqual(wallet_cache["reserved_outpoints"], {})
            self.assertNotIn("reserved_change", wallet_cache)
            stored = json.loads(wallet_file.read_text(encoding="utf-8"))[wallet_name]
            account = stored["accounts"]["bip84-account-0"]
            self.assertEqual(account["next_change_index"], 1)
            _, _, _, replacement = self._fund_existing_fixture(Path(temporary))
            self.assertTrue(
                replacement["outputs"][1]["derivation_path"].endswith("/1/1")
            )

    def test_broadcast_failure_followed_by_cancel_keeps_change_issued(self):
        with tempfile.TemporaryDirectory() as temporary:
            wallet_file, cache_file, wallet_name, funded = (
                self._fund_from_sendall_fixture(Path(temporary))
            )
            signed = sign_funded_transaction(
                funded,
                wallet_name,
                None,
                wallet_file,
                cache_file,
                "testnet4",
            )
            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                broadcast_signed_transaction(
                    signed,
                    "testnet4",
                    FailingBroadcastBackend("testnet4", signed["txid"]),
                    cache_file=cache_file,
                    wallet_file=wallet_file,
                )
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
            self.assertTrue(cache["wallets"][wallet_name]["reserved_outpoints"])
            self.assertNotIn("reserved_change", cache["wallets"][wallet_name])
            release_transaction_draft(cache_file, wallet_name, funded["draft_id"])
            stored = json.loads(wallet_file.read_text(encoding="utf-8"))[wallet_name]
            self.assertEqual(
                stored["accounts"]["bip84-account-0"]["next_change_index"], 1
            )
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
            self.assertNotIn("reserved_change", cache["wallets"][wallet_name])

    def test_reservation_age_does_not_expire_the_state_machine(self):
        with tempfile.TemporaryDirectory() as temporary:
            wallet_file, cache_file, wallet_name, funded = (
                self._fund_from_sendall_fixture(Path(temporary))
            )
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
            cache["wallets"][wallet_name]["reserved_change"]["reserved_at"] = (
                datetime.now(timezone.utc) - timedelta(hours=2)
            ).isoformat()
            save_wallet_cache(cache, cache_file)
            signed = sign_funded_transaction(
                funded,
                wallet_name,
                None,
                wallet_file,
                cache_file,
                "testnet4",
            )
            backend = FakeBroadcastBackend("testnet4", signed["txid"])
            broadcast_signed_transaction(
                signed,
                "testnet4",
                backend,
                cache_file=cache_file,
                wallet_file=wallet_file,
            )
            self.assertTrue(backend.network_verified)
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
            self.assertNotIn("reserved_change", cache["wallets"][wallet_name])

    def test_repeated_sign_attempt_does_not_cancel_issued_draft(self):
        with tempfile.TemporaryDirectory() as temporary:
            wallet_file, cache_file, wallet_name, funded = (
                self._fund_from_sendall_fixture(Path(temporary))
            )
            first_signed = sign_funded_transaction(
                funded,
                wallet_name,
                None,
                wallet_file,
                cache_file,
                "testnet4",
            )
            repeated_signed = sign_funded_transaction(
                funded,
                wallet_name,
                None,
                wallet_file,
                cache_file,
                "testnet4",
            )
            self.assertEqual(repeated_signed["txid"], first_signed["txid"])
            cache = json.loads(cache_file.read_text(encoding="utf-8"))
            wallet_cache = cache["wallets"][wallet_name]
            self.assertNotIn("reserved_change", wallet_cache)
            self.assertTrue(wallet_cache["reserved_outpoints"])
            stored = json.loads(wallet_file.read_text(encoding="utf-8"))[wallet_name]
            account = stored["accounts"]["bip84-account-0"]
            self.assertEqual(account["next_change_index"], 1)
            issued = [
                item
                for item in account["issued_addresses"]
                if item["branch"] == 1 and item["index"] == 0
            ]
            self.assertEqual(len(issued), 1)
            self.assertNotIn("lifecycle_state", issued[0])


if __name__ == "__main__":
    unittest.main()
