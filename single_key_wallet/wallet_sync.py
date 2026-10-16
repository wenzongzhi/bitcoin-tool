"""Complete five-address Esplora synchronization, without private-key access."""

from copy import deepcopy

from .coin_selection import normalize_utxo, outpoint_id
from .constants import SYNC_ADDRESS_TYPES, SPEND_ADDRESS_TYPES
from .errors import SingleKeyWalletError
from .models import integer, txid
from .storage import locked_file, read_json, write_json, utc_now
from .wallet import load_wallet, validate_record
from .wallet_cache import load_cache, balance


def _status(status: dict, height: int) -> tuple[bool, int]:
    if not isinstance(status, dict) or not isinstance(status.get("confirmed"), bool):
        raise SingleKeyWalletError("invalid backend confirmation status")
    confirmed = status["confirmed"]
    if not confirmed:
        return False, 0
    block_height = integer(status.get("block_height"), maximum=height, label="block height")
    return True, height - block_height + 1


def _stats(payload: dict) -> dict:
    result = {}
    if not isinstance(payload, dict):
        raise SingleKeyWalletError("invalid backend address statistics")
    for scope in ("chain_stats", "mempool_stats"):
        values = payload.get(scope)
        if not isinstance(values, dict):
            raise SingleKeyWalletError("invalid backend address statistics")
        result[scope] = {
            key: integer(values.get(key), label="address statistics")
            for key in ("tx_count", "funded_txo_count", "spent_txo_count", "funded_txo_sum", "spent_txo_sum")
        }
    return result


def _summary(transaction: dict, tracked: dict, height: int, involved: set[str]) -> dict:
    identifier = txid(transaction.get("txid"))
    confirmed, confirmations = _status(transaction.get("status"), height)
    received, spent = 0, 0
    kinds = set(involved)
    for values, is_input in ((transaction.get("vout", []), False), (transaction.get("vin", []), True)):
        if not isinstance(values, list):
            raise SingleKeyWalletError("invalid backend transaction history")
        for value in values:
            if not isinstance(value, dict):
                raise SingleKeyWalletError("invalid backend transaction history")
            output = value.get("prevout") if is_input else value
            if output is None and is_input and value.get("is_coinbase"):
                continue
            if not isinstance(output, dict):
                raise SingleKeyWalletError("invalid backend transaction prevout")
            address = output.get("scriptpubkey_address")
            if address in tracked:
                amount = integer(output.get("value"), label="transaction value")
                kinds.add(tracked[address])
                if is_input:
                    spent += amount
                else:
                    received += amount
    return {
        "txid": identifier, "confirmed": confirmed, "confirmations": confirmations,
        "status": deepcopy(transaction["status"]), "received_sats": received,
        "spent_sats": spent, "net_sats": received - spent,
        "direction": "send" if spent else "receive", "address_types": sorted(kinds),
    }


def sync_wallet(name, wallet_file, cache_file, network, backend) -> dict:
    record = load_wallet(name, wallet_file, network)
    if getattr(backend, "network", None) != network:
        raise SingleKeyWalletError("backend network does not match single-key wallet")
    backend.verify_network()
    height = integer(backend.get_tip_height(), maximum=0xFFFFFFFF, label="tip height")
    tip_hash = txid(backend.get_tip_hash())
    addresses, utxos, histories, involvement = {}, {}, {}, {}
    tracked = {entry["address"]: kind for kind, entry in record["addresses"].items()}
    for kind in SYNC_ADDRESS_TYPES:
        address_entry = record["addresses"][kind]
        address = address_entry["address"]
        addresses[kind] = {**deepcopy(address_entry), **_stats(backend.get_address(address))}
        remote_utxos = backend.get_address_utxos(address)
        if not isinstance(remote_utxos, list):
            raise SingleKeyWalletError("invalid backend UTXO response")
        for remote in remote_utxos:
            if not isinstance(remote, dict):
                raise SingleKeyWalletError("invalid backend UTXO")
            confirmed, confirmations = _status(remote.get("status"), height)
            item = normalize_utxo({
                "txid": remote.get("txid"), "vout": remote.get("vout"), "value": remote.get("value"),
                "address": address, "address_type": kind, "script_pubkey": address_entry["script_pubkey"],
                "confirmed": confirmed, "confirmations": confirmations,
            })
            point = outpoint_id(item)
            if point in utxos:
                raise SingleKeyWalletError("backend returned a duplicate or conflicting UTXO")
            utxos[point] = item
        history = backend.get_all_address_transactions(address)
        if not isinstance(history, list):
            raise SingleKeyWalletError("invalid backend transaction history")
        for transaction in history:
            if not isinstance(transaction, dict):
                raise SingleKeyWalletError("invalid backend transaction history")
            identifier = txid(transaction.get("txid"))
            _status(transaction.get("status"), height)
            existing = histories.get(identifier)
            if existing is None or transaction["status"]["confirmed"]:
                histories[identifier] = transaction
            involvement.setdefault(identifier, set()).add(kind)
    if backend.get_tip_hash() != tip_hash:
        raise SingleKeyWalletError("chain tip changed during synchronization; retry singlekey-syncwallet")
    summaries = [_summary(value, tracked, height, involvement[identifier]) for identifier, value in histories.items()]
    entry = {
        "wallet_id": record["wallet_id"], "wallet_name": name, "network": network,
        "synced_at": utc_now(), "tip_height": height, "tip_hash": tip_hash,
        "addresses": addresses, "utxos": list(utxos.values()),
        "transactions": sorted(summaries, key=lambda v: (v["confirmed"], -v["status"].get("block_time", 0), v["txid"])),
    }
    # Merge the newest reservations after network I/O, never a stale snapshot.
    with locked_file(wallet_file), locked_file(cache_file):
        current = read_json(wallet_file, {}).get(name)
        validate_record(current, network)
        if current["wallet_id"] != record["wallet_id"]:
            raise SingleKeyWalletError("wallet changed during synchronization")
        cache = load_cache(cache_file, network)
        previous = cache["wallets"].get(name, {})
        if previous.get("wallet_id") == record["wallet_id"]:
            entry["reservations"] = deepcopy(previous.get("reservations", {}))
            entry["pending_transactions"] = deepcopy(previous.get("pending_transactions", {}))
            entry["pending_spent_outpoints"] = deepcopy(previous.get("pending_spent_outpoints", {}))
            for identifier in histories:
                pending = entry["pending_transactions"].get(identifier)
                if pending:
                    pending["status"] = "confirmed" if histories[identifier]["status"]["confirmed"] else "mempool"
                    operation_id = pending["operation_id"]
                    entry["reservations"] = {
                        point: reservation for point, reservation in entry["reservations"].items()
                        if reservation.get("operation_id") != operation_id
                    }
            entry["pending_spent_outpoints"] = {
                point: value for point, value in entry["pending_spent_outpoints"].items()
                if point in utxos or value["txid"] not in histories
            }
        cache["wallets"][name] = entry
        write_json(cache_file, cache)
    return {"wallet_name": name, "network": network, "address_count": len(addresses),
            "utxo_count": len(utxos), "transaction_count": len(summaries), **balance(entry)}
