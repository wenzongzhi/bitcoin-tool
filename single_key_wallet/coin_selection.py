"""Deterministic selection with distinct compressed/uncompressed input sizes."""

from decimal import Decimal, InvalidOperation, ROUND_CEILING

from .codec import compact_size, serialize_output
from .constants import (
    SPEND_ADDRESS_TYPES, ADDRESS_TYPE_P2WPKH, ADDRESS_TYPE_P2PKH_UNCOMPRESSED,
    MAX_MONEY,
)
from .errors import SingleKeyTransactionError
from .models import integer, txid, TxOutput
from .scripts import dust_threshold


def parse_fee_rate(value) -> Decimal:
    try:
        rate = Decimal(str(value))
    except (ValueError, InvalidOperation) as exc:
        raise SingleKeyTransactionError("fee rate must be a decimal sat/vB value") from exc
    if not rate.is_finite() or not 0 < rate <= 10_000:
        raise SingleKeyTransactionError("fee rate must be greater than zero and at most 10000 sat/vB")
    return rate


def fee_for_vsize(vsize: int, rate: Decimal) -> int:
    integer(vsize, 1, 400_000, "vsize")
    return int((rate * vsize).to_integral_value(rounding=ROUND_CEILING))


def estimate_signed_vsize(count: int, kind: str, outputs: list[TxOutput]) -> int:
    integer(count, 1, 10_000, "input count")
    if kind not in SPEND_ADDRESS_TYPES:
        raise SingleKeyTransactionError("spending not yet supported for source address type")
    overhead = 8 + len(compact_size(count)) + len(compact_size(len(outputs)))
    output_size = sum(len(serialize_output(v)) for v in outputs)
    if kind == ADDRESS_TYPE_P2WPKH:
        return ((overhead + count * 41 + output_size) * 4 + 2 + 109 * count + 3) // 4
    # Maximum DER+sighash push, plus the selected SEC public-key serialization.
    input_size = 181 if kind == ADDRESS_TYPE_P2PKH_UNCOMPRESSED else 149
    return overhead + input_size * count + output_size


def normalize_utxo(item: dict) -> dict:
    try:
        identifier = txid(item["txid"])
        vout = integer(item["vout"], maximum=0xFFFFFFFF, label="vout")
        value = integer(item["value"], 1, MAX_MONEY, "UTXO value")
        confirmed = item["confirmed"]
        confirmations = integer(item["confirmations"], label="confirmations")
        kind, address, script = item["address_type"], item["address"], item["script_pubkey"]
        if not isinstance(confirmed, bool) or not isinstance(address, str) or not address:
            raise ValueError
        if not isinstance(kind, str) or not isinstance(script, str) or not bytes.fromhex(script):
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise SingleKeyTransactionError("invalid cached UTXO metadata") from exc
    return {
        "txid": identifier, "vout": vout, "value": value,
        "address": address, "address_type": kind, "script_pubkey": script.lower(),
        "confirmed": confirmed, "confirmations": confirmations,
    }


def outpoint_id(item: dict) -> str:
    return f"{item['txid']}:{item['vout']}"


def select_coins(utxos, kind, rate, destination_script, source_script, *, amount_sats=None,
                 send_all=False, min_confirmations=1, unavailable=None, max_fee_sats=None) -> dict:
    if kind not in SPEND_ADDRESS_TYPES:
        raise SingleKeyTransactionError("spending not yet supported for source address type")
    if not isinstance(send_all, bool) or send_all == (amount_sats is not None):
        raise SingleKeyTransactionError("provide exactly one of amount_sats or send_all")
    integer(min_confirmations, 1, MAX_MONEY, "minimum confirmations")
    if max_fee_sats is not None:
        integer(max_fee_sats, label="max fee")
    rate = parse_fee_rate(rate)
    normalized = [normalize_utxo(v) for v in utxos]
    points = [outpoint_id(v) for v in normalized]
    if len(points) != len(set(points)):
        raise SingleKeyTransactionError("duplicate UTXOs in wallet cache")
    candidates = sorted(
        (v for v in normalized if v["address_type"] == kind and v["confirmed"]
         and v["confirmations"] >= min_confirmations and outpoint_id(v) not in (unavailable or set())),
        key=lambda v: (-v["value"], v["txid"], v["vout"]),
    )
    if not candidates:
        raise SingleKeyTransactionError("wallet has no eligible UTXOs for the selected source type")
    total, selected, change = 0, [], 0
    if send_all:
        selected = candidates
        total = sum(v["value"] for v in selected)
        estimate = estimate_signed_vsize(len(selected), kind, [TxOutput(0, destination_script)])
        fee = fee_for_vsize(estimate, rate)
        destination = total - fee
    else:
        integer(amount_sats, 1, MAX_MONEY, "amount")
        destination = amount_sats
        if destination < dust_threshold(destination_script):
            raise SingleKeyTransactionError("destination amount would be dust")
        for item in candidates:
            selected.append(item)
            total += item["value"]
            outputs = [TxOutput(destination, destination_script), TxOutput(0, source_script)]
            estimate = estimate_signed_vsize(len(selected), kind, outputs)
            fee = fee_for_vsize(estimate, rate)
            change = total - destination - fee
            if change >= dust_threshold(source_script):
                break
            estimate = estimate_signed_vsize(len(selected), kind, outputs[:1])
            minimum_fee = fee_for_vsize(estimate, rate)
            if total - destination >= minimum_fee:
                change, fee = 0, total - destination
                break
        else:
            raise SingleKeyTransactionError("insufficient funds for amount and transaction fee")
    if max_fee_sats is not None and fee > max_fee_sats:
        raise SingleKeyTransactionError(f"estimated fee {fee} sats exceeds max fee {max_fee_sats} sats")
    integer(total, 1, MAX_MONEY, "total input")
    if destination <= 0:
        raise SingleKeyTransactionError("transaction fee consumes the entire balance")
    if destination < dust_threshold(destination_script):
        raise SingleKeyTransactionError("send-all destination would be dust")
    if estimate * 4 > 400_000:
        raise SingleKeyTransactionError("transaction exceeds standard weight limit")
    return {
        "selected": selected, "input_total_sats": total,
        "destination_amount_sats": destination, "change_amount_sats": change,
        "estimated_fee_sats": fee, "estimated_vsize": estimate,
    }
