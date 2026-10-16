"""Public platform API for fixed-key wallets, independent of HD services."""

from copy import deepcopy
from pathlib import Path

from btc.chainparams import NETWORK_MAINNET, get_chain_params
from network import EsploraBackend

from .constants import RECEIVE_ADDRESS_TYPES, SYNC_ADDRESS_TYPES, SPEND_ADDRESS_TYPES
from .errors import SingleKeyWalletError, SingleKeyTransactionError
from .storage import (
    default_single_key_wallet_file, default_single_key_cache_file, locked_file,
    read_json, write_json,
)
from . import wallet, wallet_sync, transaction
from .wallet_cache import load_cache, read_entry, balance


class SingleKeyWalletService:
    def __init__(self, wallet_file=None, cache_file=None, network=NETWORK_MAINNET, backend_factory=None):
        try:
            get_chain_params(network)
        except ValueError as exc:
            raise SingleKeyWalletError(str(exc)) from exc
        self.network = network
        self.wallet_file = Path(wallet_file) if wallet_file is not None else default_single_key_wallet_file(network=network)
        self.cache_file = Path(cache_file) if cache_file is not None else default_single_key_cache_file(network=network)
        self.backend_factory = backend_factory or (lambda selected: EsploraBackend(network=selected))
        if self.wallet_file.resolve() == self.cache_file.resolve():
            raise SingleKeyWalletError("wallet and cache must use different files")

    def create_wallet(self, wallet_name, password=None):
        return wallet.create_wallet(wallet_name, self.wallet_file, self.network, password)

    def import_private_key_hex(self, wallet_name, private_key_hex, password=None):
        return wallet.create_wallet(wallet_name, self.wallet_file, self.network, password, private_key_hex=private_key_hex)

    def import_private_key_wif(self, wallet_name, wif, password=None):
        return wallet.create_wallet(wallet_name, self.wallet_file, self.network, password, wif=wif)

    def list_wallets(self):
        with locked_file(self.wallet_file):
            wallets = read_json(self.wallet_file, {})
        result = []
        for name, record in wallets.items():
            wallet.validate_record(record, self.network)
            result.append(wallet.public_record(name, record))
        return result

    def get_wallet_state(self, wallet_name):
        record = wallet.load_wallet(wallet_name, self.wallet_file, self.network)
        public = wallet.public_record(wallet_name, record)
        with locked_file(self.cache_file):
            cache = load_cache(self.cache_file, self.network)
            entry = cache["wallets"].get(wallet_name)
        public["balance"] = balance(entry) if entry and entry.get("wallet_id") == record["wallet_id"] else None
        return public

    def get_addresses(self, wallet_name):
        return deepcopy(wallet.load_wallet(wallet_name, self.wallet_file, self.network)["addresses"])

    def get_receive_address(self, wallet_name, address_type=None):
        record = wallet.load_wallet(wallet_name, self.wallet_file, self.network)
        kind = address_type or record["preferences"]["default_receive_address_type"]
        if kind not in RECEIVE_ADDRESS_TYPES:
            raise SingleKeyWalletError("receiving with this address type is not supported in v1")
        return {"wallet_name": wallet_name, "address_type": kind, **deepcopy(record["addresses"][kind])}

    def sync_wallet(self, wallet_name):
        return wallet_sync.sync_wallet(wallet_name, self.wallet_file, self.cache_file, self.network, self.backend_factory(self.network))

    def _entry(self, name):
        record = wallet.load_wallet(name, self.wallet_file, self.network)
        return read_entry(self.cache_file, self.network, name, record)

    def get_balance(self, wallet_name):
        return balance(self._entry(wallet_name))

    def list_unspent(self, wallet_name, address_type=None, min_confirmations=0):
        if address_type is not None and address_type not in SYNC_ADDRESS_TYPES:
            raise SingleKeyWalletError("unknown single-key address type")
        transaction.integer(min_confirmations, label="minimum confirmations")
        entry = self._entry(wallet_name)
        unavailable = set(entry.get("reservations", {})) | set(entry.get("pending_spent_outpoints", {}))
        return [
            {**deepcopy(v), "spend_supported": v["address_type"] in SPEND_ADDRESS_TYPES,
             "reserved_or_pending": transaction.outpoint_id(v) in unavailable}
            for v in entry["utxos"] if (address_type is None or v["address_type"] == address_type)
            and v["confirmations"] >= min_confirmations
        ]

    def list_transactions(self, wallet_name, limit=20):
        transaction.integer(limit, 1, 100_000, "transaction limit")
        return deepcopy(self._entry(wallet_name)["transactions"][:limit])

    def prepare_send(self, wallet_name, from_address_type, to_address, fee_rate_sat_vb,
                     *, synchronize=True, **options):
        if from_address_type not in SPEND_ADDRESS_TYPES:
            raise SingleKeyTransactionError("spending not yet supported for source address type")
        transaction.destination_script(to_address, self.network)
        transaction.parse_fee_rate(fee_rate_sat_vb)
        backend = self.backend_factory(self.network) if synchronize else None
        if backend is not None:
            wallet_sync.sync_wallet(wallet_name, self.wallet_file, self.cache_file, self.network, backend)
        return transaction.prepare_send(wallet_name, self.wallet_file, self.cache_file, self.network,
                                        from_address_type, to_address, fee_rate_sat_vb, backend=backend, **options)

    def broadcast(self, signed_transaction, *, allow_mainnet=False):
        return transaction.broadcast(signed_transaction, self.wallet_file, self.cache_file,
                                     self.network, self.backend_factory(self.network), allow_mainnet=allow_mainnet)

    def validate_send(self, signed_transaction):
        record = wallet.load_wallet(signed_transaction.get("wallet_name"), self.wallet_file, self.network)
        transaction.validate_signed_document(signed_transaction, record, self.network)
        return deepcopy(signed_transaction)

    def cancel_send(self, wallet_name, operation_id):
        transaction.cancel_draft(wallet_name, operation_id, self.wallet_file, self.cache_file, self.network)

    def send(self, wallet_name, from_address_type, to_address, fee_rate_sat_vb,
             *, broadcast=False, allow_mainnet=False, **options):
        if broadcast and self.network == NETWORK_MAINNET and not allow_mainnet:
            raise SingleKeyTransactionError("mainnet broadcasting is disabled unless --allow-mainnet is supplied")
        document = self.prepare_send(wallet_name, from_address_type, to_address, fee_rate_sat_vb, **options)
        return self.broadcast(document, allow_mainnet=allow_mainnet) if broadcast else document

    def change_password(self, wallet_name, password=None, new_password=None):
        return wallet.change_password(wallet_name, self.wallet_file, self.network, password, new_password)

    def remove_wallet(self, wallet_name, password=None):
        wallet.validate_wallet_name(wallet_name)
        # Wallet -> cache is the lock order for lifecycle mutations.
        with locked_file(self.wallet_file):
            wallets = read_json(self.wallet_file, {})
            record = wallets.get(wallet_name)
            wallet.validate_record(record, self.network)
            key = wallet.unlock_private_key(wallet_name, record, password)
            del key
            with locked_file(self.cache_file):
                cache = load_cache(self.cache_file, self.network)
                entry = cache["wallets"].get(wallet_name, {})
                if entry.get("reservations") or entry.get("pending_spent_outpoints"):
                    raise SingleKeyWalletError("wallet has reserved or pending transaction inputs")
                del wallets[wallet_name]
                write_json(self.wallet_file, wallets)
                cache["wallets"].pop(wallet_name, None)
                write_json(self.cache_file, cache)
