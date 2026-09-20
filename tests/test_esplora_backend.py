import unittest
from http.client import RemoteDisconnected
from unittest.mock import patch

from network.esplora_backend import EsploraBackend, EsploraError


class FakeResponse:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self, limit=-1):
        return self.payload if limit < 0 else self.payload[:limit]


class EsploraBackendTest(unittest.TestCase):
    @patch("network.esplora_backend.urlopen")
    def test_broadcast_uses_text_plain_post(self, urlopen):
        txid = "ab" * 32
        urlopen.return_value = FakeResponse(txid.encode("ascii"))
        backend = EsploraBackend("https://example.invalid/api", network="testnet4")
        self.assertEqual(backend.broadcast_transaction("00"), txid)
        request = urlopen.call_args.args[0]
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(request.full_url, "https://example.invalid/api/tx")
        self.assertEqual(request.data, b"00")
        self.assertEqual(request.get_header("Content-type"), "text/plain")

    @patch("network.esplora_backend.urlopen")
    def test_fee_estimates_preserve_decimal_values(self, urlopen):
        urlopen.return_value = FakeResponse(b'{"1": 2.5, "6": 1.01}')
        backend = EsploraBackend("https://example.invalid/api", network="testnet4")
        estimates = backend.get_fee_estimates()
        self.assertEqual(str(estimates["1"]), "2.5")
        self.assertEqual(str(estimates["6"]), "1.01")

    @patch("network.esplora_backend.urlopen")
    def test_transaction_status_validates_and_returns_confirmation(self, urlopen):
        txid = "ab" * 32
        urlopen.return_value = FakeResponse(
            b'{"confirmed":true,"block_height":123,"block_hash":"'
            + b"cd" * 32
            + b'","block_time":1700000000}'
        )
        backend = EsploraBackend("https://example.invalid/api", network="testnet4")

        status = backend.get_transaction_status(txid.upper())

        self.assertTrue(status["confirmed"])
        self.assertEqual(status["block_height"], 123)
        request = urlopen.call_args.args[0]
        self.assertEqual(
            request.full_url,
            f"https://example.invalid/api/tx/{txid}/status",
        )

    def test_transaction_status_rejects_invalid_txid_without_network_request(self):
        backend = EsploraBackend("https://example.invalid/api", network="testnet4")

        with self.assertRaisesRegex(EsploraError, "64 hexadecimal"):
            backend.get_transaction_status("123")

    @patch("network.esplora_backend.time.sleep")
    @patch("network.esplora_backend.urlopen")
    def test_get_retries_remote_disconnect(self, urlopen, sleep):
        urlopen.side_effect = [
            RemoteDisconnected("remote closed"),
            FakeResponse(b"123"),
        ]
        backend = EsploraBackend(
            "https://example.invalid/api",
            network="testnet4",
            retries=1,
        )
        self.assertEqual(backend.get_tip_height(), 123)
        self.assertEqual(urlopen.call_count, 2)
        sleep.assert_called_once_with(0.5)

    @patch("network.esplora_backend.time.sleep")
    @patch("network.esplora_backend.urlopen")
    def test_post_is_not_retried_after_remote_disconnect(self, urlopen, sleep):
        urlopen.side_effect = RemoteDisconnected("remote closed")
        backend = EsploraBackend(
            "https://example.invalid/api",
            network="testnet4",
            retries=5,
        )
        with self.assertRaisesRegex(EsploraError, r"POST /tx failed"):
            backend.broadcast_transaction("00")
        self.assertEqual(urlopen.call_count, 1)
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
