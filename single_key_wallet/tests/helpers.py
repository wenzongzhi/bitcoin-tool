from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from single_key_wallet import SingleKeyWalletService
from single_key_wallet.codec import metrics, serialize
from single_key_wallet.constants import SYNC_ADDRESS_TYPES
from single_key_wallet.models import Transaction, TxInput, TxOutput

KEY_HEX = "0" * 63 + "1"
KEY = bytes.fromhex(KEY_HEX)
COMPRESSED_WIF = "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
UNCOMPRESSED_WIF = "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"


class FakeBackend:
    def __init__(self, network, addresses, values=(50_000, 70_000)):
        self.network = network
        self.base_url = "https://fake.invalid/api"
        self.queries = []
        self.parents = {}
        self.utxos = {}
        self.history = {}
        self.stats = {}
        self.broadcasts = []
        self.fail_broadcast = False
        self.fail_history = False
        self.tip = "ab" * 32
        for offset, (kind, entry) in enumerate(addresses.items()):
            address = entry["address"]
            self.utxos[address] = []
            self.history[address] = []
            for index, value in enumerate(values):
                parent = Transaction(
                    [TxInput(f"{offset + 1:02x}" * 32, index)],
                    [TxOutput(value, bytes.fromhex(entry["script_pubkey"]))],
                )
                identifier = metrics(parent)["txid"]
                self.parents[identifier] = serialize(parent).hex()
                status = {"confirmed": True, "block_height": 90, "block_time": 10 + index}
                self.utxos[address].append({"txid": identifier, "vout": 0, "value": value, "status": status})
                self.history[address].append({
                    "txid": identifier, "status": status,
                    "vin": [{"is_coinbase": True}],
                    "vout": [{"scriptpubkey_address": address, "value": value}],
                })
            self.stats[address] = {
                "chain_stats": {"tx_count": len(values), "funded_txo_count": len(values),
                                "spent_txo_count": 0, "funded_txo_sum": sum(values), "spent_txo_sum": 0},
                "mempool_stats": {"tx_count": 0, "funded_txo_count": 0, "spent_txo_count": 0,
                                  "funded_txo_sum": 0, "spent_txo_sum": 0},
            }

    def verify_network(self):
        self.queries.append(("network", self.network))

    def get_tip_height(self):
        return 100

    def get_tip_hash(self):
        return self.tip

    def get_address(self, address):
        self.queries.append(("stats", address))
        return deepcopy(self.stats[address])

    def get_address_utxos(self, address):
        self.queries.append(("utxos", address))
        return deepcopy(self.utxos[address])

    def get_all_address_transactions(self, address):
        self.queries.append(("history", address))
        if self.fail_history:
            raise RuntimeError("fake interrupted history")
        return deepcopy(self.history[address])

    def get_transaction_hex(self, identifier):
        return self.parents[identifier]

    def broadcast_transaction(self, raw_hex):
        self.broadcasts.append(raw_hex)
        if self.fail_broadcast:
            from network import EsploraError
            raise EsploraError("simulated disconnect after POST")
        from single_key_wallet.codec import deserialize
        return metrics(deserialize(raw_hex))["txid"]


class WalletFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.wallet_file = self.directory / "single_key_wallets.json"
        self.cache_file = self.directory / "single_key_wallet_cache.json"
        self.service = SingleKeyWalletService(self.wallet_file, self.cache_file, "testnet4")
        self.service.import_private_key_hex("test", KEY_HEX, "password")
        self.addresses = self.service.get_addresses("test")
        self.backend = FakeBackend("testnet4", self.addresses)
        self.service.backend_factory = lambda network: self.backend

    def synchronize(self):
        self.service.sync_wallet("test")

    def prepare(self, kind="p2wpkh", **options):
        return self.service.prepare_send(
            "test", kind, self.addresses["p2wpkh"]["address"], "2.5",
            password="password", **options,
        )


def assert_no_secret_fields(test, value):
    forbidden = {"private_key", "private_key_hex", "wif", "secret", "password", "mnemonic",
                 "path", "derivation_path", "account_id", "branch", "index"}
    if isinstance(value, dict):
        test.assertFalse(forbidden & set(value))
        for child in value.values():
            assert_no_secret_fields(test, child)
    elif isinstance(value, list):
        for child in value:
            assert_no_secret_fields(test, child)
