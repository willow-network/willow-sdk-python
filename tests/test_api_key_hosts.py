"""The API key goes only to the hosts it was configured for: the API and an
indexer_url the caller sets, never a discovered indexer or the consensus RPC."""

import httpx
import pytest

from willow import WillowClient


def _envelope(data):
    return {"success": True, "data": data, "error": None}


def _indexer_list(endpoint):
    return _envelope([{
        "indexer_did": "did:willow:idx", "subgroves": ["sg"], "stake_amount": 1,
        "endpoint": endpoint, "query_endpoint": endpoint,
        "status": "active", "performance_score": 99.0, "last_update": 0,
    }])


@pytest.mark.asyncio
async def test_a_discovered_indexer_gets_no_api_key():
    seen = []

    def handler(request):
        seen.append((request.url.host, request.url.path, request.headers.get("x-api-key")))
        if request.url.path == "/indexers":
            return httpx.Response(200, json=_indexer_list("https://indexer.example"))
        return httpx.Response(200, json={"columns": [], "rows": [], "row_count": 0})

    client = WillowClient("https://api.test", api_key="wk_secret")
    transport = httpx.MockTransport(handler)
    client._http = httpx.AsyncClient(transport=transport, headers={"X-API-Key": "wk_secret"})
    client._indexer_http = httpx.AsyncClient(transport=transport)
    client.indexers._http = client._http
    await client.indexing.sql_query("sg", "select 1")
    assert ("api.test", "/indexers", "wk_secret") in seen
    assert ("indexer.example", "/sql/sg", None) in seen
    assert all(key is None for host, _, key in seen if host != "api.test")
    await client.close()


@pytest.mark.asyncio
async def test_a_configured_indexer_url_gets_the_api_key():
    seen = []

    def handler(request):
        seen.append((request.url.host, request.headers.get("x-api-key")))
        return httpx.Response(200, json={"columns": [], "rows": [], "row_count": 0})

    client = WillowClient("https://api.test", api_key="wk_secret", indexer_url="https://my-indexer.example")
    transport = httpx.MockTransport(handler)
    client._http = httpx.AsyncClient(transport=transport, headers={"X-API-Key": "wk_secret"})
    client._indexer_http = httpx.AsyncClient(transport=transport)
    await client.indexing.sql_query("sg", "select 1")
    assert seen == [("my-indexer.example", "wk_secret")]
    await client.close()


@pytest.mark.asyncio
async def test_the_completeness_anchor_read_carries_no_api_key():
    seen = []

    def handler(request):
        seen.append((request.url.host, request.headers.get("x-api-key")))
        return httpx.Response(200, json={"result": {"response": {"code": 1, "log": "none"}}})

    client = WillowClient("http://api.test:3031", api_key="wk_secret")
    client._rpc_http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client.completeness._rpc_http = client._rpc_http
    with pytest.raises(Exception):
        await client.completeness.fetch_anchor("sg", 1)
    assert seen == [("api.test", None)]
    await client.close()
