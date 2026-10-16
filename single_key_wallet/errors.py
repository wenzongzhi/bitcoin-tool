"""Errors belonging exclusively to the single-key wallet platform."""


class SingleKeyWalletError(Exception):
    pass


class SingleKeyTransactionError(SingleKeyWalletError):
    pass
