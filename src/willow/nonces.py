"""Transaction nonces handed out per signing DID.

The node accepts a transaction under a nonce in ``base + 1 … base + 24``
that is not used yet. ``base`` is the account's nonce: it advances only over
used nonces with no gap below them. Reading ``base + 1`` for every write gives
two writes in flight the same nonce, and a nonce taken but never used (its
transaction refused at CheckTx or dropped from the mempool) blocks the window
until something uses it.

``NonceTracker`` keeps, per DID, the nonces handed out that haven't landed
(each with the time it was handed out) and the nonces seen used above the
base. It hands out the lowest nonce in the window that is neither, under a
lock; a nonce handed out more than 120 s ago (the node's admission hold) that
hasn't landed is free again. It takes back a nonce whose transaction was
refused without using it, so no gap is left behind.
"""

import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, FrozenSet, Iterable, Optional, Set, Tuple

from .errors import TransactionError

#: How many nonces above the base the node accepts.
WINDOW = 24
#: Seconds a nonce handed out stays taken while its transaction hasn't landed.
LEASE_SECONDS = 120.0

# CometBFT's answer to a transaction whose exact bytes are already in its
# mempool cache (pending, or committed recently), as the API passes it on:
# "CometBFT RPC error -32603: Internal error tx already exists in cache".
_IN_CACHE = re.compile(r"tx already exists in cache\s*\Z")


def already_in_cache(message: Optional[str]) -> bool:
    """Whether a submission's error says CometBFT already holds these exact
    bytes: CheckTx admitted an identical copy, so this one counts as
    accepted."""
    return isinstance(message, str) and _IN_CACHE.search(message) is not None


def _refusal_patterns(nonce: Optional[int]) -> Tuple["re.Pattern[str]", "re.Pattern[str]", "re.Pattern[str]"]:
    # The node's own forms, anchored, for this transaction's nonce: a log
    # that only quotes them (a signature mismatch quotes the whole expected
    # message, user data included) says nothing about the nonce.
    n = r"\d+" if nonce is None else str(int(nonce))
    return (
        re.compile(rf"Nonce {n} of \S+ is held by a pending transaction"),
        re.compile(rf"Invalid nonce: {n} (?:already used|<= base nonce)"),
        re.compile(rf"\(nonce {n} spent\)\s*\Z"),
    )


#: The nonce is free again.
FREE = "free"
#: A pending transaction holds the nonce: it stays taken until its lease runs out.
HELD = "held"
#: The nonce is used: no transaction under it can run again.
USED = "used"
#: Unknown whether the transaction reached the node: the nonce stays taken
#: until its lease runs out.
UNKNOWN = "unknown"


def refusal_outcome(
    error: BaseException, http_status: Optional[int] = None, nonce: Optional[int] = None
) -> str:
    """What a failed submission leaves its nonce as: ``FREE``, ``HELD``,
    ``USED``, or ``UNKNOWN``.

    A CheckTx refusal (a ``TransactionError`` with an ``error_code``) frees
    the nonce unless its log is the node's own refusal of ``nonce``: it
    starts ``Nonce <nonce> of <did> is held by a pending transaction``
    (``HELD``), or ``Invalid nonce: <nonce> already used`` or ``Invalid
    nonce: <nonce> <= base nonce`` (``USED``), or ends ``(nonce <nonce>
    spent)`` (``USED``). Pass the transaction's ``nonce``; without it any
    nonce matches. An HTTP 4xx answer with no CheckTx code is the API
    refusing the body before it reached the node, which frees it too.
    Anything else (a network error, a gateway error) may have reached the
    node.
    """
    if isinstance(error, TransactionError) and error.error_code is not None:
        log = error.raw_log if error.raw_log is not None else error.message
        held, used, spent = _refusal_patterns(nonce)
        if held.match(log):
            return HELD
        if used.match(log) or spent.search(log):
            return USED
        return FREE
    if isinstance(error, TransactionError) and http_status is not None and 400 <= http_status < 500:
        return FREE
    return UNKNOWN


def parse_nonce_state(value: bytes) -> Tuple[int, FrozenSet[int]]:
    """An account's nonce state from the value of the ABCI query
    ``/store/account_nonce_state/{did}``: ``(base, used)``.

    The value is the base as a big-endian u64, then 3 bytes in which bit
    ``i % 8`` of byte ``i / 8`` marks ``base + 1 + i`` used. 8 bytes is the
    base alone (``/store/account_nonce``); none is an account with no
    transaction yet.

    Raises:
        ValueError: The value is another length.
    """
    value = bytes(value)
    if len(value) == 0:
        return 0, frozenset()
    if len(value) not in (8, 11):
        raise ValueError(f"a nonce state of {len(value)} bytes; the node answers 8 or 11")
    base = int.from_bytes(value[:8], "big")
    bitmap = int.from_bytes(value[8:], "little")
    return base, frozenset(base + 1 + i for i in range(WINDOW) if bitmap >> i & 1)


@dataclass
class _Account:
    base: int = 0
    used: Set[int] = field(default_factory=set)
    handed: Dict[int, float] = field(default_factory=dict)


class NonceTracker:
    """The nonces one client has handed out, per signing DID.

    Thread-safe; nothing in it awaits, so two coroutines can't take the same
    nonce either.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        self._accounts: Dict[str, _Account] = {}

    def _account(self, did: str) -> _Account:
        account = self._accounts.get(did)
        if account is None:
            account = self._accounts[did] = _Account()
        return account

    def _refresh(self, account: _Account, base: int, now: float, used: Iterable[int] = ()) -> None:
        # The highest base seen: a lagging answer can't hand out a used nonce.
        # A nonce once used stays used.
        account.base = max(account.base, base)
        account.used = {n for n in account.used.union(used) if n > account.base}
        account.handed = {
            n: at for n, at in account.handed.items()
            if n > account.base and n not in account.used and now - at < LEASE_SECONDS
        }

    def observe(self, did: str, base: int, used: Iterable[int] = ()) -> int:
        """Record ``did``'s base, and the nonces above it the node reports
        used, as the node answered them; returns the highest base seen."""
        with self._lock:
            account = self._account(did)
            self._refresh(account, base, self._clock(), used)
            return account.base

    def is_used(self, did: str, nonce: int) -> bool:
        """Whether ``nonce`` of ``did`` is known used: at or below the highest
        base seen, or seen used above it."""
        with self._lock:
            account = self._account(did)
            return nonce <= account.base or nonce in account.used

    def take(self, did: str, base: int, used: Iterable[int] = ()) -> Optional[int]:
        """Hand out the lowest nonce in ``did``'s window that isn't used or
        handed out, given the base (and the nonces above it used) the node
        answered; ``None`` when every one is."""
        with self._lock:
            account = self._account(did)
            now = self._clock()
            self._refresh(account, base, now, used)
            for nonce in range(account.base + 1, account.base + WINDOW + 1):
                if nonce not in account.used and nonce not in account.handed:
                    account.handed[nonce] = now
                    return nonce
            return None

    def hold(self, did: str, nonce: int) -> None:
        """Mark ``nonce`` handed out for a transaction whose nonce is fixed
        (RegisterDid signs nonce 1)."""
        with self._lock:
            account = self._account(did)
            if nonce > account.base:
                account.handed[nonce] = self._clock()

    def handed_at(self, did: str, nonce: int) -> Optional[float]:
        """When ``nonce`` was handed out, while its lease runs; else ``None``."""
        with self._lock:
            account = self._account(did)
            self._refresh(account, account.base, self._clock())
            return account.handed.get(nonce)

    def reclaim(self, did: str, nonce: int, handed_at: Optional[float]) -> bool:
        """Take ``nonce`` again for a resubmission of the transaction it was
        handed out for at ``handed_at`` (what ``handed_at()`` answered then),
        renewing its lease; a nonce known used is not taken again.

        Returns ``False`` when this tracker has since handed the nonce to
        another transaction (the first one's lease ran out first).
        """
        with self._lock:
            account = self._account(did)
            now = self._clock()
            self._refresh(account, account.base, now)
            at = account.handed.get(nonce)
            if at is not None and at != handed_at:
                return False
            if nonce > account.base and nonce not in account.used:
                account.handed[nonce] = now
            return True

    def settle(self, did: str, nonce: int, outcome: str) -> None:
        """Record what a failed submission left ``nonce`` as (see
        ``refusal_outcome``)."""
        with self._lock:
            account = self._account(did)
            if outcome == FREE:
                account.handed.pop(nonce, None)
            elif outcome == USED:
                account.handed.pop(nonce, None)
                if nonce > account.base:
                    account.used.add(nonce)

    def release(self, did: str, nonce: int) -> None:
        """Give back a nonce handed out for a transaction that was never sent."""
        self.settle(did, nonce, FREE)
