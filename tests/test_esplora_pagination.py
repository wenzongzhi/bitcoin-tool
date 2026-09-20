import unittest

from network.esplora_backend import EsploraBackend, EsploraError


def transaction(number: int, *, confirmed: bool = True) -> dict:
    return {
        "txid": f"{number:064x}",
        "status": {"confirmed": confirmed},
        "vin": [],
        "vout": [],
    }


class PagedBackend(EsploraBackend):
    def __init__(self, first_page, chain_pages):
        super().__init__("https://example.invalid/api", network="testnet4")
        self.first_page = first_page
        self.chain_pages = list(chain_pages)
        self.paths = []

    def _get_json(self, path):
        self.paths.append(path)
        if path.endswith("/txs"):
            return self.first_page
        if not self.chain_pages:
            raise AssertionError(f"unexpected pagination request: {path}")
        page = self.chain_pages.pop(0)
        if isinstance(page, Exception):
            raise page
        return page


class EsploraPaginationTest(unittest.TestCase):
    def _backend_for_count(self, count):
        values = [transaction(number) for number in range(count, 0, -1)]
        first = values[:25]
        remaining = values[25:]
        pages = [remaining[offset : offset + 25] for offset in range(0, len(remaining), 25)]
        pages.append([])
        return PagedBackend(first, pages)

    def test_complete_history_sizes(self):
        for count in (0, 1, 24, 25, 26, 51, 101):
            with self.subTest(count=count):
                backend = self._backend_for_count(count)
                result = backend.get_all_address_transactions("tb1qhistory")
                self.assertEqual(len(result), count)
                self.assertEqual(len({item["txid"] for item in result}), count)

    def test_keeps_mempool_and_replaces_duplicate_with_confirmed_version(self):
        duplicate = transaction(500, confirmed=False)
        confirmed_duplicate = transaction(500, confirmed=True)
        first = [duplicate, *[transaction(number) for number in range(25, 0, -1)]]
        backend = PagedBackend(first, [[confirmed_duplicate, transaction(0)], []])

        result = backend.get_all_address_transactions("tb1qmixed")

        self.assertEqual(len(result), 27)
        matching = [item for item in result if item["txid"] == duplicate["txid"]]
        self.assertEqual(len(matching), 1)
        self.assertTrue(matching[0]["status"]["confirmed"])

    def test_empty_next_page_terminates_cleanly(self):
        backend = PagedBackend([transaction(1)], [[]])
        self.assertEqual(len(backend.get_all_address_transactions("tb1qempty")), 1)

    def test_malformed_page_is_an_explicit_error(self):
        backend = PagedBackend([transaction(1)], [[{"txid": "bad"}]])
        with self.assertRaisesRegex(EsploraError, "invalid transaction"):
            backend.get_all_address_transactions("tb1qmalformed")

    def test_backend_failure_during_pagination_is_an_explicit_error(self):
        backend = PagedBackend(
            [transaction(number) for number in range(25, 0, -1)],
            [EsploraError("offline")],
        )
        with self.assertRaisesRegex(EsploraError, "cannot complete.*offline"):
            backend.get_all_address_transactions("tb1qoffline")

    def test_repeated_cursor_stops_instead_of_looping(self):
        repeated = transaction(1)
        backend = PagedBackend([repeated], [[repeated]])
        with self.assertRaisesRegex(EsploraError, "did not advance"):
            backend.get_all_address_transactions("tb1qloop")


if __name__ == "__main__":
    unittest.main()
