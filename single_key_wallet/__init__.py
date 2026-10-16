"""Independent single-key wallet platform."""

from .constants import (
    SINGLE_KEY_WALLET_VERSION, SPEND_ADDRESS_TYPES, RECEIVE_ADDRESS_TYPES, SYNC_ADDRESS_TYPES,
    ADDRESS_TYPE_P2PKH_COMPRESSED, ADDRESS_TYPE_P2PKH_UNCOMPRESSED,
    ADDRESS_TYPE_P2WPKH, ADDRESS_TYPE_P2SH_P2WPKH, ADDRESS_TYPE_P2TR,
)
from .errors import SingleKeyWalletError, SingleKeyTransactionError
from .service import SingleKeyWalletService
from .storage import default_single_key_wallet_file, default_single_key_cache_file

__all__ = [
    "SingleKeyWalletError", "SingleKeyTransactionError", "SingleKeyWalletService",
    "default_single_key_wallet_file", "default_single_key_cache_file",
    "SINGLE_KEY_WALLET_VERSION", "SPEND_ADDRESS_TYPES", "RECEIVE_ADDRESS_TYPES", "SYNC_ADDRESS_TYPES",
    "ADDRESS_TYPE_P2PKH_COMPRESSED", "ADDRESS_TYPE_P2PKH_UNCOMPRESSED", "ADDRESS_TYPE_P2WPKH",
    "ADDRESS_TYPE_P2SH_P2WPKH", "ADDRESS_TYPE_P2TR",
]
