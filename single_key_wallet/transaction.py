"""Isolated fixed-key funding, signing, preflight, and durable broadcast state."""

from copy import deepcopy
from datetime import datetime, timezone
from decimal import Decimal
import re
import uuid

from .codec import deserialize, metrics, serialize
from .coin_selection import fee_for_vsize, normalize_utxo, outpoint_id, parse_fee_rate, select_coins
from .constants import SPEND_ADDRESS_TYPES
from .errors import SingleKeyWalletError, SingleKeyTransactionError
from .models import Transaction, TxInput, TxOutput, integer
from .scripts import destination_script, dust_threshold
from .signing import sign_transaction, verify_all_inputs
from .storage import locked_file, write_json, utc_now
from .wallet import load_wallet, unlock_private_key
from .wallet_cache import load_cache, require_entry, unavailable_outpoints

SIGNED_FORMAT = "bitcoin-tool-single-key-signed-transaction"


def _release(cache_file, network, name, operation_id) -> None:
    with locked_file(cache_file):
        cache = load_cache(cache_file, network)
        entry = cache["wallets"].get(name)
        if entry is not None:
            entry["reservations"] = {
                point: reservation for point, reservation in entry.get("reservations", {}).items()
                if reservation.get("operation_id") != operation_id
            }
            write_json(cache_file, cache)


def cancel_draft(name, operation_id, wallet_file, cache_file, network) -> None:
    record = load_wallet(name, wallet_file, network)
    with locked_file(cache_file):
        cache = load_cache(cache_file, network)
        entry = require_entry(cache, name, record)
        reservations = entry.get("reservations", {})
        matching = [v for v in reservations.values() if v.get("operation_id") == operation_id]
        if not matching:
            raise SingleKeyTransactionError("single-key transaction draft does not exist")
        if any(v.get("broadcast_attempted") for v in matching):
            raise SingleKeyTransactionError("broadcast outcome must be reconciled before releasing these UTXOs")
        entry["reservations"] = {p: v for p, v in reservations.items() if v.get("operation_id") != operation_id}
        write_json(cache_file, cache)


def _validate_previous_transactions(prevouts, backend) -> None:
    parents = {}
    for item in prevouts:
        identifier = item["txid"]
        if identifier not in parents:
            parent = deserialize(backend.get_transaction_hex(identifier))
            if metrics(parent)["txid"] != identifier:
                raise SingleKeyTransactionError("backend prevout transaction id mismatch")
            parents[identifier] = parent
        parent = parents[identifier]
        if item["vout"] >= len(parent.outputs):
            raise SingleKeyTransactionError("prevout output does not exist")
        output = parent.outputs[item["vout"]]
        if output.value != item["value"] or output.script_pubkey.hex() != item["script_pubkey"]:
            raise SingleKeyTransactionError("cached prevout value or script does not match its transaction")
        if (len(parent.inputs) == 1 and parent.inputs[0].txid == "00" * 32
            and parent.inputs[0].vout == 0xFFFFFFFF and item["confirmations"] < 100):
            raise SingleKeyTransactionError("coinbase output has not reached 100 confirmations")


def prepare_send(name, wallet_file, cache_file, network, from_address_type, to_address, rate,
                 *, amount_sats=None, send_all=False, password=None, min_confirmations=1,
                 max_fee_sats=None, max_cache_age_seconds=300, backend=None) -> dict:
    if from_address_type not in SPEND_ADDRESS_TYPES:
        raise SingleKeyTransactionError("spending not yet supported for source address type")
    record = load_wallet(name, wallet_file, network)
    source = record["addresses"][from_address_type]
    script = destination_script(to_address, network)
    rate = parse_fee_rate(rate)
    integer(max_cache_age_seconds, label="max cache age")
    operation_id = uuid.uuid4().hex
    with locked_file(cache_file):
        cache = load_cache(cache_file, network)
        entry = require_entry(cache, name, record)
        try:
            synchronized = datetime.fromisoformat(entry["synced_at"].replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - synchronized).total_seconds()
            if synchronized.tzinfo is None or age < -60 or age > max_cache_age_seconds:
                raise ValueError
        except (KeyError, TypeError, ValueError) as exc:
            raise SingleKeyTransactionError("single-key cache is stale or invalid; synchronize the wallet") from exc
        for raw in entry.get("utxos", []):
            item = normalize_utxo(raw)
            if item["address_type"] == from_address_type and (
                item["address"] != source["address"] or item["script_pubkey"] != source["script_pubkey"]
            ):
                raise SingleKeyTransactionError("cached UTXO does not belong to the selected wallet address")
        selection = select_coins(
            entry["utxos"], from_address_type, rate, script, bytes.fromhex(source["script_pubkey"]),
            amount_sats=amount_sats, send_all=send_all, min_confirmations=min_confirmations,
            unavailable=unavailable_outpoints(cache), max_fee_sats=max_fee_sats,
        )
        for item in selection["selected"]:
            entry.setdefault("reservations", {})[outpoint_id(item)] = {
                "operation_id": operation_id, "reserved_at": utc_now(), "broadcast_attempted": False,
            }
        write_json(cache_file, cache)
    key = None
    try:
        prevouts = selection["selected"]
        if backend is not None:
            if backend.network != network:
                raise SingleKeyTransactionError("backend network mismatch")
            backend.verify_network()
            _validate_previous_transactions(prevouts, backend)
        outputs = [TxOutput(selection["destination_amount_sats"], script)]
        if selection["change_amount_sats"]:
            outputs.append(TxOutput(selection["change_amount_sats"], bytes.fromhex(source["script_pubkey"])))
        tx = Transaction([TxInput(v["txid"], v["vout"]) for v in prevouts], outputs)
        key = unlock_private_key(name, record, password)
        # DER length can change when an output changes. Increase the fee monotonically.
        for _ in range(8):
            measured = sign_transaction(tx, prevouts, key)
            fee = selection["input_total_sats"] - sum(v.value for v in tx.outputs)
            required = fee_for_vsize(measured["vsize"], rate)
            if max_fee_sats is not None and max(fee, required) > max_fee_sats:
                raise SingleKeyTransactionError(
                    f"final fee {max(fee, required)} sats exceeds max fee {max_fee_sats} sats; transaction was not broadcast"
                )
            if fee >= required:
                break
            adjustable = tx.outputs[0] if send_all else tx.outputs[-1] if len(tx.outputs) == 2 else None
            if adjustable is None:
                raise SingleKeyTransactionError("signed fee is below requested rate and no change is available")
            adjustable.value -= required - fee
            if adjustable.value < dust_threshold(adjustable.script_pubkey):
                raise SingleKeyTransactionError("fee correction would create a dust output")
        else:
            raise SingleKeyTransactionError("could not reach requested fee rate")
        if measured["weight"] > 400_000:
            raise SingleKeyTransactionError("signed transaction exceeds standard weight limit")
        document = {
            "format": SIGNED_FORMAT, "version": 1, "network": network,
            "wallet_name": name, "wallet_id": record["wallet_id"], "operation_id": operation_id,
            "created_at": utc_now(), "source_address_type": from_address_type,
            "source_address": source["address"], "destination": to_address,
            "send_mode": "all" if send_all else "amount", "inputs": deepcopy(prevouts),
            "outputs": [
                {"value": v.value, "script_pubkey": v.script_pubkey.hex(), "is_change": index == 1,
                 "address": source["address"] if index == 1 else to_address}
                for index, v in enumerate(tx.outputs)
            ],
            "input_total_sats": selection["input_total_sats"],
            "destination_amount_sats": tx.outputs[0].value,
            "change_amount_sats": tx.outputs[1].value if len(tx.outputs) == 2 else 0,
            "fee_sats": fee, "estimated_fee_sats": selection["estimated_fee_sats"],
            "requested_fee_rate_sat_vb": format(rate, "f"),
            "fee_rate_sat_vb": format(Decimal(fee) / measured["vsize"], "f"),
            "max_fee_sats": max_fee_sats, "input_count": len(prevouts),
            "hex": serialize(tx).hex(), "complete": True, **measured,
        }
        validate_signed_document(document, record, network)
        return document
    except BaseException:
        _release(cache_file, network, name, operation_id)
        raise
    finally:
        if key is not None:
            del key


def validate_signed_document(document: dict, record: dict, network: str) -> tuple[Transaction, list[dict]]:
    try:
        allowed = {
            "format", "version", "network", "wallet_name", "wallet_id", "operation_id", "created_at",
            "source_address_type", "source_address", "destination", "send_mode", "inputs", "outputs",
            "input_total_sats", "input_count", "destination_amount_sats", "change_amount_sats",
            "fee_sats", "estimated_fee_sats", "requested_fee_rate_sat_vb", "fee_rate_sat_vb",
            "max_fee_sats", "hex", "complete", "txid", "wtxid", "size", "weight", "vsize",
        }
        if set(document) != allowed:
            raise ValueError
        if re.fullmatch(r"[a-f0-9]{32}", document["operation_id"]) is None:
            raise ValueError
        if (document["format"] != SIGNED_FORMAT or document["version"] != 1
            or document["network"] != network or document["wallet_id"] != record["wallet_id"]
            or document["complete"] is not True):
            raise ValueError
        kind = document["source_address_type"]
        if kind not in SPEND_ADDRESS_TYPES:
            raise ValueError
        source = record["addresses"][kind]
        if document["source_address"] != source["address"]:
            raise ValueError
        tx = deserialize(document["hex"])
        prevouts = [normalize_utxo(v) for v in document["inputs"]]
        if any(set(original) != set(normalized) for original, normalized in zip(document["inputs"], prevouts)):
            raise ValueError
        if not verify_all_inputs(tx, prevouts):
            raise SingleKeyTransactionError("local signature verification failed")
        for v in prevouts:
            if v["address_type"] != kind or v["address"] != source["address"] or v["script_pubkey"] != source["script_pubkey"]:
                raise ValueError
        outputs = document["outputs"]
        if len(outputs) != len(tx.outputs) or len(outputs) not in (1, 2):
            raise ValueError
        if document["send_mode"] not in ("all", "amount") or (document["send_mode"] == "all" and len(outputs) != 1):
            raise ValueError
        for index, (metadata, output) in enumerate(zip(outputs, tx.outputs)):
            if (set(metadata) != {"value", "script_pubkey", "is_change", "address"}
                or metadata["value"] != output.value or metadata["script_pubkey"] != output.script_pubkey.hex()
                or metadata["is_change"] is not (index == 1)
                or destination_script(metadata["address"], network) != output.script_pubkey
                or output.value < dust_threshold(output.script_pubkey)):
                raise ValueError
        if outputs[0]["address"] != document["destination"]:
            raise ValueError
        if len(outputs) == 2 and (outputs[1]["address"] != source["address"] or outputs[1]["script_pubkey"] != source["script_pubkey"]):
            raise ValueError
        total = sum(v["value"] for v in prevouts)
        integer(total, label="total input")
        fee = total - sum(v.value for v in tx.outputs)
        measured = metrics(tx)
        expected = {**measured, "input_total_sats": total, "input_count": len(prevouts),
                    "destination_amount_sats": tx.outputs[0].value,
                    "change_amount_sats": tx.outputs[1].value if len(outputs) == 2 else 0, "fee_sats": fee,
                    "fee_rate_sat_vb": format(Decimal(fee) / measured["vsize"], "f")}
        if any(document.get(k) != v for k, v in expected.items()) or fee < 0 or measured["weight"] > 400_000:
            raise ValueError
        rate = parse_fee_rate(document["requested_fee_rate_sat_vb"])
        if fee < fee_for_vsize(measured["vsize"], rate):
            raise SingleKeyTransactionError("final fee is below the requested rate")
        maximum = document["max_fee_sats"]
        if maximum is not None:
            integer(maximum, label="max fee")
            if fee > maximum:
                raise SingleKeyTransactionError(
                    f"final fee {fee} sats exceeds max fee {maximum} sats; transaction was not broadcast"
                )
        return tx, prevouts
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise SingleKeyTransactionError("invalid single-key signed transaction metadata") from exc


def broadcast(document, wallet_file, cache_file, network, backend, *, allow_mainnet=False) -> dict:
    if network == "mainnet" and not allow_mainnet:
        raise SingleKeyTransactionError("mainnet broadcasting is disabled unless --allow-mainnet is supplied")
    name = document.get("wallet_name")
    record = load_wallet(name, wallet_file, network)
    tx, prevouts = validate_signed_document(document, record, network)
    if backend.network != network:
        raise SingleKeyTransactionError("backend network mismatch")
    backend.verify_network()
    _validate_previous_transactions(prevouts, backend)
    identifier, operation = metrics(tx)["txid"], document["operation_id"]
    with locked_file(cache_file):
        cache = load_cache(cache_file, network)
        entry = require_entry(cache, name, record)
        cached = {outpoint_id(v): normalize_utxo(v) for v in entry["utxos"]}
        reservations = entry.get("reservations", {})
        for item in prevouts:
            point = outpoint_id(item)
            reservation = reservations.get(point)
            current = cached.get(point)
            fields = ("txid", "vout", "value", "address", "address_type", "script_pubkey")
            if (not current or not current["confirmed"] or current["confirmations"] < 1
                or any(current[field] != item[field] for field in fields) or not isinstance(reservation, dict)
                or reservation.get("operation_id") != operation):
                raise SingleKeyTransactionError("input is no longer reserved by this transaction")
            pending_spent = entry.get("pending_spent_outpoints", {}).get(point)
            if pending_spent is not None:
                pending = entry.get("pending_transactions", {}).get(identifier)
                if (pending_spent.get("txid") != identifier or pending is None
                    or pending.get("signed_transaction", {}).get("hex") != document["hex"]
                    or pending.get("status") != "broadcast_unknown"):
                    raise SingleKeyTransactionError("transaction input already has a broadcast attempt")
        # Persist intent before POST: a disconnect may happen after remote acceptance.
        for item in prevouts:
            point = outpoint_id(item)
            reservations[point]["broadcast_attempted"] = True
            entry.setdefault("pending_spent_outpoints", {})[point] = {"txid": identifier, "operation_id": operation}
        entry.setdefault("pending_transactions", {})[identifier] = {
            "txid": identifier, "operation_id": operation, "status": "broadcast_unknown",
            "attempted_at": utc_now(), "signed_transaction": deepcopy(document),
        }
        write_json(cache_file, cache)
    remote = backend.broadcast_transaction(document["hex"])
    if remote != identifier:
        raise SingleKeyTransactionError("broadcast returned a different transaction id; outcome must be reconciled")
    try:
        with locked_file(cache_file):
            cache = load_cache(cache_file, network)
            entry = require_entry(cache, name, record)
            entry["pending_transactions"][identifier]["status"] = "broadcast"
            entry["reservations"] = {p: v for p, v in entry["reservations"].items() if v.get("operation_id") != operation}
            write_json(cache_file, cache)
    except SingleKeyWalletError:
        return {**deepcopy(document), "broadcast": True, "cache_warning": "broadcast accepted; cache update failed"}
    return {**deepcopy(document), "broadcast": True}
