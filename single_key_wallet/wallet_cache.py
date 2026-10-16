"""Public-only cache, balance semantics, and fixed-key UTXO reservations."""

from copy import deepcopy
from pathlib import Path

from .coin_selection import normalize_utxo, outpoint_id
from .constants import SYNC_ADDRESS_TYPES, SPEND_ADDRESS_TYPES
from .errors import SingleKeyWalletError
from .storage import default_single_key_cache_file, read_json, write_json, locked_file

CACHE_VERSION = 1


def load_cache(path: Path, network: str) -> dict:
    cache = read_json(path, {"version": CACHE_VERSION, "network": network, "wallets": {}})
    if (cache.get("version") != CACHE_VERSION or cache.get("network") != network
        or not isinstance(cache.get("wallets"), dict)):
        raise SingleKeyWalletError("invalid single-key cache format or network")
    return cache


def require_entry(cache: dict, name: str, record: dict) -> dict:
    entry = cache["wallets"].get(name)
    if not isinstance(entry, dict) or entry.get("wallet_id") != record["wallet_id"]:
        raise SingleKeyWalletError("single-key wallet has no matching cache; run singlekey-syncwallet")
    return entry


def unavailable_outpoints(cache: dict) -> set[str]:
    return {
        point
        for entry in cache["wallets"].values()
        for field in ("reservations", "pending_spent_outpoints")
        for point in entry.get(field, {})
    }


def read_entry(path: Path, network: str, name: str, record: dict) -> dict:
    with locked_file(path):
        return deepcopy(require_entry(load_cache(path, network), name, record))


def balance(entry: dict) -> dict:
    per_type = {}
    unavailable = set(entry.get("reservations", {})) | set(entry.get("pending_spent_outpoints", {}))
    for kind in SYNC_ADDRESS_TYPES:
        stats = entry["addresses"][kind]
        chain = stats["chain_stats"]
        pool = stats["mempool_stats"]
        confirmed = chain["funded_txo_sum"] - chain["spent_txo_sum"]
        unconfirmed = pool["funded_txo_sum"] - pool["spent_txo_sum"]
        per_type[kind] = {
            "confirmed_balance_sats": confirmed, "unconfirmed_balance_sats": unconfirmed,
            "balance_sats": confirmed + unconfirmed,
            "spend_supported": kind in SPEND_ADDRESS_TYPES,
            "available_confirmed_sats": sum(
                item["value"] for item in entry["utxos"] if item["address_type"] == kind
                and item["confirmed"] and item["confirmations"] >= 1
                and outpoint_id(item) not in unavailable
            ) if kind in SPEND_ADDRESS_TYPES else 0,
        }
    return {
        "detected_balance_sats": sum(v["balance_sats"] for v in per_type.values()),
        "spendable_balance_sats": sum(v["balance_sats"] for v in per_type.values() if v["spend_supported"]),
        "available_confirmed_sats": sum(v["available_confirmed_sats"] for v in per_type.values()),
        "per_address_type": per_type, "synced_at": entry["synced_at"],
    }
