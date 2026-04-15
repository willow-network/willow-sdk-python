"""Tests for WillowIndexers discovery client + source routing enums.

These tests exercise the standalone indexers module without touching
the full client / auth / consensus stack.
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from willow.indexers import (
    NoIndexersReachableError,
    QuerySource,
    RoutedQueryResult,
    ServedBy,
    ValidatorHasNoDataError,
    WillowIndexers,
)
from willow.types import IndexerInfo, IndexerStatus


def _info(did: str, subgroves: list[str], perf: float, status: str = "active") -> IndexerInfo:
    return IndexerInfo(
        indexer_did=did,
        subgroves=subgroves,
        stake_amount=100,
        endpoint=f"http://{did}:9090",
        query_endpoint=f"http://{did}:3032",
        status=IndexerStatus(status),
        performance_score=perf,
        last_update=0,
    )


def test_effective_query_endpoint_prefers_query_endpoint():
    i = _info("x", ["sg"], 100.0)
    assert i.effective_query_endpoint() == "http://x:3032"


def test_effective_query_endpoint_falls_back_to_endpoint():
    i = _info("x", ["sg"], 100.0)
    i.query_endpoint = None
    assert i.effective_query_endpoint() == "http://x:9090"


def test_query_source_default_is_auto():
    """Callers that forget to pass a source should get the sensible default."""
    # We don't have a function-level default in the enum itself, but the
    # library's contract is that omitting source means AUTO. This test pins
    # that AUTO is importable and distinct from the other variants.
    assert QuerySource.AUTO != QuerySource.VALIDATOR
    assert QuerySource.AUTO != QuerySource.INDEXER
    assert QuerySource("auto") == QuerySource.AUTO


@pytest.mark.asyncio
async def test_explicit_override_returns_synthetic_entry():
    http = httpx.AsyncClient()
    try:
        disc = WillowIndexers(
            http,
            "http://validator:3031",
            indexer_url="http://pinned:3032",
        )
        assert disc.has_explicit_override()
        # for_subgrove must short-circuit without making any HTTP calls.
        picks = await disc.for_subgrove("anything")
        assert len(picks) == 1
        assert picks[0].effective_query_endpoint() == "http://pinned:3032"
        all_ = await disc.list()
        assert len(all_) == 1
    finally:
        await http.aclose()


@pytest.mark.asyncio
async def test_list_fetches_and_caches(monkeypatch):
    """Within the cache TTL, subsequent `list()` calls must not hit the network."""
    calls = []

    async def fake_get(self, url, *args, **kwargs):
        calls.append(url)
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = lambda: None
        resp.json = lambda: {
            "success": True,
            "data": [
                {
                    "indexer_did": "a",
                    "subgroves": ["sg-1"],
                    "stake_amount": 100,
                    "endpoint": "http://a:9090",
                    "query_endpoint": "http://a:3032",
                    "status": "active",
                    "performance_score": 90.0,
                    "last_update": 0,
                }
            ],
        }
        return resp

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    http = httpx.AsyncClient()
    try:
        disc = WillowIndexers(http, "http://validator:3031", cache_ttl_seconds=10)
        first = await disc.list()
        second = await disc.list()
        assert len(calls) == 1, f"should cache within TTL, got {len(calls)} calls"
        assert first[0].indexer_did == "a"
        assert second == first
    finally:
        await http.aclose()


@pytest.mark.asyncio
async def test_for_subgrove_filters_and_sorts(monkeypatch):
    async def fake_get(self, url, *args, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status = lambda: None
        resp.json = lambda: {
            "success": True,
            "data": [
                {
                    "indexer_did": "slow",
                    "subgroves": ["sg-shared"],
                    "stake_amount": 1,
                    "endpoint": "http://slow:9090",
                    "query_endpoint": "http://slow:3032",
                    "status": "active",
                    "performance_score": 40.0,
                    "last_update": 0,
                },
                {
                    "indexer_did": "fast",
                    "subgroves": ["sg-shared"],
                    "stake_amount": 1,
                    "endpoint": "http://fast:9090",
                    "query_endpoint": "http://fast:3032",
                    "status": "active",
                    "performance_score": 99.0,
                    "last_update": 0,
                },
                {
                    "indexer_did": "other",
                    "subgroves": ["sg-other"],
                    "stake_amount": 1,
                    "endpoint": "http://other:9090",
                    "query_endpoint": "http://other:3032",
                    "status": "active",
                    "performance_score": 100.0,
                    "last_update": 0,
                },
                {
                    "indexer_did": "inactive",
                    "subgroves": ["sg-shared"],
                    "stake_amount": 1,
                    "endpoint": "http://inactive:9090",
                    "query_endpoint": "http://inactive:3032",
                    "status": "inactive",
                    "performance_score": 100.0,
                    "last_update": 0,
                },
            ],
        }
        return resp

    monkeypatch.setattr(httpx.AsyncClient, "get", fake_get)

    http = httpx.AsyncClient()
    try:
        disc = WillowIndexers(http, "http://validator:3031")
        picks = await disc.for_subgrove("sg-shared")
        # Inactive filtered out, best performer first.
        assert [i.indexer_did for i in picks] == ["fast", "slow"]
    finally:
        await http.aclose()


def test_evict_removes_from_cache(monkeypatch):
    """After eviction, the evicted indexer must not appear in subsequent lookups."""
    http = httpx.AsyncClient()
    try:
        disc = WillowIndexers(http, "http://validator:3031")
        # Prime the cache manually so we don't need HTTP mocks
        from willow.indexers import _CacheEntry

        disc._cache = _CacheEntry(
            data=[_info("a", ["sg-1"], 100.0), _info("b", ["sg-1"], 50.0)],
            fetched_at=time.monotonic(),
        )
        disc.evict("a")
        assert {i.indexer_did for i in disc._cache.data} == {"b"}
        # Evicting an absent DID is a no-op, not an error
        disc.evict("absent")
        assert {i.indexer_did for i in disc._cache.data} == {"b"}
    finally:
        pass


def test_validator_has_no_data_error_has_context():
    e = ValidatorHasNoDataError("sg-x", "VerifyOnly retention")
    assert "sg-x" in str(e)
    assert "VerifyOnly" in str(e)
    assert e.subgrove_id == "sg-x"


def test_no_indexers_reachable_error_has_context():
    e = NoIndexersReachableError("sg-x", "all timed out")
    assert "sg-x" in str(e)
    assert "all timed out" in str(e)
    assert e.subgrove_id == "sg-x"


def test_routed_query_result_shape():
    r = RoutedQueryResult(result={"ok": True}, source=ServedBy.INDEXER, indexer_did="a")
    assert r.source == ServedBy.INDEXER
    assert r.indexer_did == "a"
    assert r.fallback is False  # default
