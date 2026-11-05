"""ConsensusClient looks a transaction up by its hash as CometBFT's JSON-RPC
``tx`` method takes it: the hash's bytes in base64 (a ``[]byte`` parameter
in a JSON-RPC body), not the hex the API answers it in."""

import base64
import json

import pytest
from multidict import CIMultiDict

from willow.consensus import ConsensusClient, ConsensusConfig
from willow.consensus.types import TransactionStatus

HASH = "0A1B2C3D" * 8


class _Body:
    def __init__(self, data):
        self._data = data

    async def read(self, n=-1):
        n = len(self._data) if n < 0 else n
        chunk, self._data = self._data[:n], self._data[n:]
        return chunk


class _Response:
    def __init__(self, payload):
        self.status = 200
        self.headers = CIMultiDict()
        self.content = _Body(json.dumps(payload).encode())

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _Rpc:
    """A CometBFT RPC that knows one transaction, by its hash's bytes."""

    def __init__(self, code=0, answered_hash=HASH):
        self.asked = []
        self._code = code
        self._answered_hash = answered_hash

    def post(self, url, json):
        assert url == "http://rpc.test" and json["method"] == "tx"
        self.asked.append(json["params"])
        if base64.b64decode(json["params"]["hash"], validate=True) != bytes.fromhex(HASH):
            return _Response({"jsonrpc": "2.0", "id": 1, "error": {
                "code": -32603, "message": "Internal error", "data": f"tx ({HASH}) not found",
            }})
        return _Response({"jsonrpc": "2.0", "id": 1, "result": {
            "hash": self._answered_hash, "height": "7", "index": 0,
            "tx_result": {"code": self._code, "log": ""}, "tx": "",
        }})


def _client(rpc):
    client = ConsensusClient(ConsensusConfig(consensus_rpc_url="http://rpc.test", max_retries=0))
    client._session = rpc
    return client


@pytest.mark.asyncio
@pytest.mark.parametrize("given", [HASH, HASH.lower(), "0x" + HASH])
async def test_a_transaction_is_looked_up_by_its_hash_in_base64(given):
    rpc = _Rpc()
    assert await _client(rpc).get_transaction_status(given) == TransactionStatus.SUCCESS
    assert rpc.asked == [{"hash": base64.b64encode(bytes.fromhex(HASH)).decode(), "prove": False}]


@pytest.mark.asyncio
async def test_a_refused_transaction_is_found_failed_and_waited_for():
    assert await _client(_Rpc(code=5)).wait_for_transaction(HASH, timeout_secs=1) == TransactionStatus.FAILED


@pytest.mark.asyncio
async def test_an_answer_for_another_transaction_is_not_this_ones():
    rpc = _Rpc(answered_hash="FF" * 32)
    assert await _client(rpc).get_transaction_status(HASH) == TransactionStatus.NOT_FOUND


@pytest.mark.asyncio
async def test_a_hash_that_isnt_hex_raises_before_any_request():
    rpc = _Rpc()
    with pytest.raises(ValueError):
        await _client(rpc).get_transaction_status("not-a-hash")
    assert rpc.asked == []
