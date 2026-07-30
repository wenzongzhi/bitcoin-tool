"""
Copyright 2026 温中志 (Wen Zhongzhi)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from btc.chainparams import NETWORK_MAINNET, get_chain_params

DEFAULT_ESPLORA_URL = get_chain_params(NETWORK_MAINNET).default_esplora_url


class EsploraError(Exception):
    pass


class EsploraBackend:
    def __init__(
        self,
        base_url: str | None = None,
        timeout: int = 20,
        network: str = NETWORK_MAINNET,
    ):
        try:
            self.params = get_chain_params(network)
        except ValueError as exc:
            raise EsploraError(str(exc)) from exc
        self.network = network
        base_url = base_url or self.params.default_esplora_url
        self.base_url = base_url.rstrip("/")
        if not self.base_url.startswith(("http://", "https://")):
            raise EsploraError("backend URL must start with http:// or https://")
        if timeout <= 0:
            raise EsploraError("backend timeout must be positive")
        self.timeout = timeout

    def _get_text(self, path: str) -> str:
        request = Request(
            f"{self.base_url}{path}",
            headers={"User-Agent": "bitcoin-tool/utxo-sync"},
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                return response.read().decode("utf-8")
        except HTTPError as exc:
            raise EsploraError(f"Esplora HTTP error {exc.code} for {path}") from exc
        except URLError as exc:
            raise EsploraError(f"cannot reach Esplora backend: {exc.reason}") from exc
        except OSError as exc:
            raise EsploraError(f"cannot read Esplora response: {exc}") from exc

    def _get_json(self, path: str):
        text = self._get_text(path)
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise EsploraError(f"invalid JSON response for {path}") from exc

    def get_tip_height(self) -> int:
        try:
            return int(self._get_text("/blocks/tip/height"))
        except ValueError as exc:
            raise EsploraError("invalid tip height response") from exc

    def get_tip_hash(self) -> str:
        tip_hash = self._get_text("/blocks/tip/hash").strip()
        if not re.fullmatch(r"[0-9a-fA-F]{64}", tip_hash):
            raise EsploraError("invalid tip hash response")
        return tip_hash.lower()

    def get_block_hash(self, height: int) -> str:
        if isinstance(height, bool) or not isinstance(height, int) or height < 0:
            raise EsploraError("block height must be a non-negative integer")
        block_hash = self._get_text(f"/block-height/{height}").strip()
        if not re.fullmatch(r"[0-9a-fA-F]{64}", block_hash):
            raise EsploraError("invalid block hash response")
        return block_hash.lower()

    def verify_network(self) -> None:
        actual_genesis = self.get_block_hash(0)
        if actual_genesis != self.params.genesis_hash:
            raise EsploraError(
                f'Esplora backend is not connected to network "{self.network}"'
            )

    def get_address(self, address: str) -> dict:
        data = self._get_json(f"/address/{quote(address, safe='')}")
        if not isinstance(data, dict):
            raise EsploraError("invalid address response")
        return data

    def get_address_utxos(self, address: str) -> list[dict]:
        data = self._get_json(f"/address/{quote(address, safe='')}/utxo")
        if not isinstance(data, list):
            raise EsploraError("invalid address UTXO response")
        return data

    def get_address_transactions(self, address: str) -> list[dict]:
        data = self._get_json(f"/address/{quote(address, safe='')}/txs")
        if not isinstance(data, list):
            raise EsploraError("invalid address transaction response")
        return data
