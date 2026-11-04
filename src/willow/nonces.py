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
from typing import Callable, Dict, Optional, Set

from .errors import TransactionError

#: How many nonces above the base the node accepts.
WINDOW = 24
#: Seconds a nonce handed out stays taken while its transaction hasn't landed.
LEASE_SECONDS = 120.0

# What a CheckTx refusal says about its nonce. "held by a pending transaction":
# another pending transaction holds it. "already used" or "<= base nonce": a
# transaction used it. "(nonce N spent)": a refusal in a block that spent it.
_HELD = re.compile(r"held by a pending transaction", re.IGNORECASE)
_USED = re.compile(r"already used|<= base nonce|nonce \d+ spent", re.IGNORECASE)

#: The nonce is free again.
FREE = "free"
#: A pending transaction holds the nonce: it stays taken until its lease runs out.
HELD = "held"
#: The nonce is used: no transaction under it can run again.
USED = "used"
#: Unknown whether the transaction reached the node: the nonce stays taken
#: until its lease runs out.
UNKNOWN = "unknown"


def refusal_outcome(error: BaseException, http_status: Optional[int] = None) -> str:
    """What a failed submission leaves its nonce as: ``FREE``, ``HELD``,
    ``USED``, or ``UNKNOWN``.

    A CheckTx refusal (a ``TransactionError`` with an ``error_code``) frees
    the nonce unless its log says the nonce is held by a pending
    transaction, already used, or spent. An HTTP 4xx answer with no CheckTx
    code is the API refusing the body before it reached the node, which
    frees it too. Anything else (a network error, a gateway error) may have
    reached the node.
    """
    if isinstance(error, TransactionError) and error.error_code is not None:
        log = error.raw_log or str(error)
        if _HELD.search(log):
            return HELD
        if _USED.search(log):
            return USED
        return FREE
    if isinstance(error, TransactionError) and http_status is not None and 400 <= http_status < 500:
        return FREE
    return UNKNOWN


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

    def _refresh(self, account: _Account, base: int, now: float) -> None:
        # The highest base seen: a lagging answer can't hand out a used nonce.
        account.base = max(account.base, base)
        account.used = {n for n in account.used if n > account.base}
        account.handed = {
            n: at for n, at in account.handed.items()
            if n > account.base and now - at < LEASE_SECONDS
        }

    def observe(self, did: str, base: int) -> int:
        """Record ``did``'s base as the node answered it; returns the highest
        base seen."""
        with self._lock:
            account = self._account(did)
            self._refresh(account, base, self._clock())
            return account.base

    def take(self, did: str, base: int) -> Optional[int]:
        """Hand out the lowest nonce in ``did``'s window that isn't used or
        handed out, given the base the node answered; ``None`` when every one
        is."""
        with self._lock:
            account = self._account(did)
            now = self._clock()
            self._refresh(account, base, now)
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
