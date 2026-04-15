"""Indexer discovery client for source-routed GraphQL / SQL queries.

The SDK's ``graphql_query`` / ``sql_query`` methods take a :class:`QuerySource`
telling the routing layer where the caller wants data served from:

- :attr:`QuerySource.VALIDATOR` — consensus-verified chain-tip. Every row is
  Merkle-provable. Fails fast for ``VerifyOnly`` subgroves.
- :attr:`QuerySource.INDEXER` — full history + analytics via an indexer.
- :attr:`QuerySource.AUTO` (default) — indexer if one serves this subgrove,
  otherwise validator. Sets ``fallback=True`` on the result when it falls back.

:class:`WillowIndexers` wraps the validator's ``GET /indexers`` endpoint with
a 30-second in-memory cache. When the client is constructed with an explicit
``indexer_url``, discovery is bypassed and a synthetic single-entry list is
returned so the routing code path stays uniform.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Generic, List, Optional, TypeVar

import httpx

from .types import IndexerInfo, IndexerStatus


class QuerySource(str, Enum):
    """Which backend should serve a query."""

    VALIDATOR = "validator"
    """Consensus-verified chain-tip. Fails fast for VerifyOnly subgroves."""

    INDEXER = "indexer"
    """Full history + analytics via an indexer. Fails if none registered."""

    AUTO = "auto"
    """Prefer indexer, fall back to validator. Sensible default."""


class ServedBy(str, Enum):
    """Which backend actually served a query."""

    VALIDATOR = "validator"
    INDEXER = "indexer"


T = TypeVar("T")


@dataclass
class RoutedQueryResult(Generic[T]):
    """Result + routing metadata.

    Makes the trust model part of the API so UIs can display it.
    """

    result: T
    """Raw response from the backend."""

    source: ServedBy
    """Which backend actually served this query."""

    indexer_did: Optional[str] = None
    """DID of the indexer that served the query. ``None`` for validator."""

    fallback: bool = False
    """``True`` when ``AUTO`` routing fell back from indexer to validator."""


DEFAULT_CACHE_TTL_SECONDS: float = 30.0


class ValidatorHasNoDataError(Exception):
    """Raised when ``QuerySource.VALIDATOR`` was requested but the validator
    has no data for the subgrove (VerifyOnly retention, pruned, not indexed).
    """

    def __init__(self, subgrove_id: str, reason: str) -> None:
        super().__init__(
            f'Validator cannot serve data for subgrove "{subgrove_id}": {reason}'
        )
        self.subgrove_id = subgrove_id
        self.reason = reason


class NoIndexersReachableError(Exception):
    """Raised when ``QuerySource.INDEXER`` was requested but either no
    indexer serves the subgrove or every candidate failed.
    """

    def __init__(self, subgrove_id: str, details: str) -> None:
        super().__init__(
            f'No indexer could serve subgrove "{subgrove_id}": {details}'
        )
        self.subgrove_id = subgrove_id
        self.details = details


@dataclass
class _CacheEntry:
    data: List[IndexerInfo] = field(default_factory=list)
    fetched_at: float = 0.0


class WillowIndexers:
    """Discovery client for the validator's ``GET /indexers`` endpoint."""

    def __init__(
        self,
        http: httpx.AsyncClient,
        api_url: str,
        indexer_url: Optional[str] = None,
        cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
    ) -> None:
        self._http = http
        self._api_url = api_url.rstrip("/")
        self._indexer_url = indexer_url
        self._cache_ttl = cache_ttl_seconds
        self._cache: Optional[_CacheEntry] = None

    def has_explicit_override(self) -> bool:
        """Whether an explicit ``indexer_url`` was configured (bypasses discovery)."""
        return self._indexer_url is not None

    def invalidate(self) -> None:
        """Force the next lookup to re-fetch ``/indexers``."""
        self._cache = None

    def evict(self, indexer_did: str) -> None:
        """Drop a specific indexer from the cache (e.g., after a 5xx response)."""
        if self._cache is None:
            return
        self._cache.data = [
            i for i in self._cache.data if i.indexer_did != indexer_did
        ]

    async def list(self) -> List[IndexerInfo]:
        """Return all registered indexers, cached for ``cache_ttl_seconds``.

        When ``indexer_url`` is set, returns a synthetic single-entry list
        instead of calling the validator.
        """
        if self._indexer_url is not None:
            return [self._synthetic_entry(self._indexer_url)]

        now = time.monotonic()
        if self._cache is not None and now - self._cache.fetched_at < self._cache_ttl:
            return list(self._cache.data)

        url = f"{self._api_url}/indexers"
        resp = await self._http.get(url)
        resp.raise_for_status()
        body = resp.json()
        data_items = body.get("data") or []
        parsed = [IndexerInfo(**item) for item in data_items]
        self._cache = _CacheEntry(data=parsed, fetched_at=now)
        return list(parsed)

    async def for_subgrove(self, subgrove_id: str) -> List[IndexerInfo]:
        """Active indexers serving ``subgrove_id``, sorted by ``performance_score`` desc.

        With an explicit ``indexer_url`` override, always returns a single
        synthetic entry — the routing code doesn't need to special-case this.
        """
        if self._indexer_url is not None:
            return [self._synthetic_entry(self._indexer_url)]

        picks = [
            i
            for i in await self.list()
            if i.status == IndexerStatus.ACTIVE and subgrove_id in i.subgroves
        ]
        picks.sort(key=lambda i: i.performance_score, reverse=True)
        return picks

    def _synthetic_entry(self, url: str) -> IndexerInfo:
        """Build a single-entry list that matches any subgrove.

        The ``subgroves=[]`` is OK because :meth:`for_subgrove` short-circuits
        before it would try to filter this entry.
        """
        return IndexerInfo(
            indexer_did="explicit-override",
            subgroves=[],
            stake_amount=0,
            endpoint=url,
            query_endpoint=url,
            status=IndexerStatus.ACTIVE,
            performance_score=100.0,
            last_update=0,
        )
