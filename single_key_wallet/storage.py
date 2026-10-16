"""Isolated application paths, file locks, and durable atomic JSON writes."""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile

from filelock import FileLock, Timeout
from platformdirs import user_data_path

from btc.chainparams import NETWORK_MAINNET, get_chain_params
from .errors import SingleKeyWalletError


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _data_file(data_dir, network, stem) -> Path:
    try:
        get_chain_params(network)
    except ValueError as exc:
        raise SingleKeyWalletError(str(exc)) from exc
    configured = data_dir or os.environ.get("BITCOIN_TOOL_DATADIR")
    directory = Path(configured).expanduser().resolve() if configured else user_data_path(
        "bitcoin-tool", appauthor=False
    )
    suffix = "" if network == NETWORK_MAINNET else f"_{network}"
    return directory / f"{stem}{suffix}.json"


def default_single_key_wallet_file(data_dir=None, network=NETWORK_MAINNET) -> Path:
    return _data_file(data_dir, network, "single_key_wallets")


def default_single_key_cache_file(data_dir=None, network=NETWORK_MAINNET) -> Path:
    return _data_file(data_dir, network, "single_key_wallet_cache")


@contextmanager
def locked_file(path: Path):
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with FileLock(str(path) + ".lock", timeout=10):
            yield
    except Timeout as exc:
        raise SingleKeyWalletError("single-key wallet data is busy") from exc
    except OSError as exc:
        raise SingleKeyWalletError("cannot access single-key wallet data") from exc


def read_json(path: Path, default: dict) -> dict:
    try:
        with Path(path).open(encoding="utf-8") as stream:
            value = json.load(stream)
    except FileNotFoundError:
        return default
    except (OSError, ValueError) as exc:
        raise SingleKeyWalletError("cannot read single-key JSON data") from exc
    if not isinstance(value, dict):
        raise SingleKeyWalletError("single-key JSON data must be an object")
    return value


def write_json(path: Path, value: dict) -> None:
    path = Path(path)
    temporary = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as stream:
            temporary = Path(stream.name)
            os.chmod(temporary, 0o600)
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except OSError as exc:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise SingleKeyWalletError("cannot write single-key JSON data") from exc
