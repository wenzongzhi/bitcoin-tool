"""Standard destination scripts, including Bech32m Taproot destinations."""

from bech32 import CHARSET, bech32_hrp_expand, bech32_polymod, convertbits

from btc.chainparams import get_chain_params
from .errors import SingleKeyWalletError, SingleKeyTransactionError
from .wif import decode_base58check


def classify_script(script: bytes) -> str | None:
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[-2:] == b"\x88\xac":
        return "p2pkh"
    if len(script) == 23 and script[:2] == b"\xa9\x14" and script[-1:] == b"\x87":
        return "p2sh"
    if len(script) == 22 and script[:2] == b"\x00\x14":
        return "p2wpkh"
    if len(script) == 34 and script[:2] == b"\x00\x20":
        return "p2wsh"
    if len(script) == 34 and script[:2] == b"\x51\x20":
        return "p2tr"
    return None


def destination_script(address: str, network: str) -> bytes:
    try:
        params = get_chain_params(network)
        if not isinstance(address, str) or not address or len(address) > 90:
            raise ValueError
        if address.lower().startswith(("bc1", "tb1", "bcrt1")):
            if address != address.lower() and address != address.upper():
                raise ValueError
            normalized = address.lower()
            split = normalized.rfind("1")
            hrp = normalized[:split]
            values = [CHARSET.index(c) for c in normalized[split + 1:]]
            if hrp != params.bech32_hrp:
                raise SingleKeyTransactionError("destination does not belong to the selected network")
            if len(values) < 7:
                raise ValueError
            version = values[0]
            checksum = bech32_polymod(bech32_hrp_expand(hrp) + values)
            if checksum != (1 if version == 0 else 0x2BC830A3):
                raise ValueError
            decoded = convertbits(values[1:-6], 5, 8, False)
            if decoded is None:
                raise ValueError
            program = bytes(decoded)
            if (version == 0 and len(program) in (20, 32)) or (version == 1 and len(program) == 32):
                return bytes([0 if version == 0 else 0x51, len(program)]) + program
            raise ValueError
        payload = decode_base58check(address)
        if len(payload) != 21:
            raise ValueError
        if payload[:1] == params.p2pkh_version:
            return b"\x76\xa9\x14" + payload[1:] + b"\x88\xac"
        if payload[:1] == params.p2sh_version:
            return b"\xa9\x14" + payload[1:] + b"\x87"
        raise SingleKeyTransactionError("destination does not belong to the selected network")
    except SingleKeyTransactionError:
        raise
    except (SingleKeyWalletError, ValueError, TypeError) as exc:
        raise SingleKeyTransactionError("invalid or unsupported destination address") from exc


def dust_threshold(script: bytes) -> int:
    kind = classify_script(script)
    try:
        return {"p2pkh": 546, "p2sh": 540, "p2wpkh": 294, "p2wsh": 330, "p2tr": 330}[kind]
    except KeyError as exc:
        raise SingleKeyTransactionError("unsupported destination script") from exc
