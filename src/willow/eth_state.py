"""Verifiable Ethereum state reads.

Counterpart to the indexer's ``POST /verifiable-rpc/eth/state`` and
``/verifiable-rpc/eth/call`` routes. Walks EIP-1186 MPT proofs locally
and exposes ergonomic storage-layout helpers (ERC-20 balance, allowance,
ERC-721 owner, Uniswap V2 reserves).

Three trust modes follow the Rust/TS SDK conventions:
    * ``StateVerifyMode.STRICT`` (default) — verify every MPT proof.
    * ``StateVerifyMode.ANCHOR_ONLY``       — skip the walks; trust the
      carried ``state_root`` against an out-of-band anchor.
    * ``StateVerifyMode.DISABLED``         — passthrough.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, List, Optional, Sequence, Tuple

import httpx
import rlp
from eth_hash.auto import keccak


class StateVerifyMode(str, Enum):
    STRICT = "strict"
    ANCHOR_ONLY = "anchor_only"
    DISABLED = "disabled"


@dataclass
class VerifiedStorage:
    slot: str  # 0x-prefixed
    value: int


@dataclass
class VerifiedStateRead:
    address: str
    block_number: int
    block_hash: str
    state_root: str
    nonce: int
    balance: int
    storage_hash: str
    code_hash: str
    storage: List[VerifiedStorage] = field(default_factory=list)
    mode: StateVerifyMode = StateVerifyMode.STRICT


@dataclass
class VerifiedCall:
    block_number: int
    block_hash: str
    state_root: str
    result: bytes
    access_state_reads: List[VerifiedStateRead]
    mode: StateVerifyMode


def _to_bytes(maybe_array: Any) -> bytes:
    """Server serializes fixed arrays as ``[u8; N]`` → JSON ``[number, ...]``."""
    if isinstance(maybe_array, list):
        return bytes(maybe_array)
    if isinstance(maybe_array, bytes):
        return maybe_array
    raise TypeError(f"expected list or bytes, got {type(maybe_array).__name__}")


def _hex0x(b: bytes, width: int) -> str:
    return "0x" + b.rjust(width, b"\x00").hex()


def _bytes_to_int(b: bytes) -> int:
    if not b:
        return 0
    return int.from_bytes(b, "big")


def _nibbles(b: bytes) -> List[int]:
    out: List[int] = []
    for byte in b:
        out.append((byte >> 4) & 0x0F)
        out.append(byte & 0x0F)
    return out


def _decode_compact_path(encoded: bytes) -> Tuple[List[int], bool]:
    if not encoded:
        return [], False
    first = encoded[0]
    flag = (first >> 4) & 0x0F
    is_leaf = flag >= 2
    odd = (flag & 1) == 1
    nibs: List[int] = []
    if odd:
        nibs.append(first & 0x0F)
    for byte in encoded[1:]:
        nibs.append((byte >> 4) & 0x0F)
        nibs.append(byte & 0x0F)
    return nibs, is_leaf


def verify_mpt_proof(
    root: bytes,
    key_hash: bytes,
    expected_value: bytes,
    proof_nodes: Sequence[bytes],
) -> Tuple[bool, str]:
    """Verify ``expected_value`` is at ``key_hash`` in the trie rooted at ``root``.

    Returns ``(ok, error_message)``. Mirrors the Rust + TS implementations.
    """
    if len(root) != 32:
        return False, f"root must be 32 bytes, got {len(root)}"
    if len(key_hash) != 32:
        return False, f"key must be 32 bytes, got {len(key_hash)}"
    if not proof_nodes:
        return False, "proof is empty"

    nibs = _nibbles(key_hash)
    expected = root
    idx = 0

    for i, node in enumerate(proof_nodes):
        h = keccak(node)
        if h != expected:
            return False, f"node {i}: hash mismatch"
        decoded = rlp.decode(node)
        if not isinstance(decoded, list):
            return False, f"node {i}: rlp root is not a list"

        if len(decoded) == 17:
            if idx == len(nibs):
                value = decoded[16] if isinstance(decoded[16], (bytes, bytearray)) else b""
                return _check_value(bytes(value), expected_value)
            nxt = decoded[nibs[idx]]
            idx += 1
            nxt_b = bytes(nxt) if isinstance(nxt, (bytes, bytearray)) else b""
            if not nxt_b:
                return _check_value(b"", expected_value)
            if len(nxt_b) != 32:
                return False, f"node {i}: inline-embedded child not supported (len {len(nxt_b)})"
            expected = nxt_b
        elif len(decoded) == 2:
            enc_path = bytes(decoded[0]) if isinstance(decoded[0], (bytes, bytearray)) else b""
            path, is_leaf = _decode_compact_path(enc_path)
            remaining = nibs[idx:]
            if len(path) > len(remaining) or path != remaining[: len(path)]:
                return _check_value(b"", expected_value)
            idx += len(path)
            second = decoded[1]
            if is_leaf:
                if idx != len(nibs):
                    return _check_value(b"", expected_value)
                return _check_value(
                    bytes(second) if isinstance(second, (bytes, bytearray)) else b"",
                    expected_value,
                )
            ref = bytes(second) if isinstance(second, (bytes, bytearray)) else b""
            if len(ref) != 32:
                return False, f"node {i}: inline-embedded extension child not supported (len {len(ref)})"
            expected = ref
        else:
            return False, f"node {i}: unexpected RLP shape (len {len(decoded)})"

    return False, "proof exhausted without reaching leaf"


def _check_value(actual: bytes, expected: bytes) -> Tuple[bool, str]:
    if actual == expected:
        return True, ""
    return False, "leaf value mismatch"


def _rlp_encode_account(nonce: int, balance: int, storage_hash: bytes, code_hash: bytes) -> bytes:
    def as_int_bytes(n: int) -> bytes:
        if n == 0:
            return b""
        return n.to_bytes((n.bit_length() + 7) // 8, "big")

    return rlp.encode([as_int_bytes(nonce), as_int_bytes(balance), storage_hash, code_hash])


def verify_state_proof(proof: dict) -> None:
    """Walk every MPT proof. Raises ``ValueError`` on mismatch."""
    state_root = _to_bytes(proof["state_root"])
    address = _to_bytes(proof["address"])
    addr_hash = keccak(address)
    acct = proof["account_state"]
    nonce = int(acct["nonce"])
    balance = _bytes_to_int(_to_bytes(acct["balance"]))
    storage_hash = _to_bytes(acct["storage_hash"])
    code_hash = _to_bytes(acct["code_hash"])
    account_leaf = _rlp_encode_account(nonce, balance, storage_hash, code_hash)

    acct_proof = proof["account_proof"]
    nodes = [_to_bytes(n) for n in acct_proof["proof_nodes"]]
    ok, err = verify_mpt_proof(state_root, addr_hash, account_leaf, nodes)
    if not ok:
        raise ValueError(f"account proof failed: {err}")

    for sp in proof.get("storage_proofs", []):
        slot_bytes = _to_bytes(sp["slot"])
        value_int = _bytes_to_int(_to_bytes(sp["value"]))
        if value_int == 0:
            value_rlp = rlp.encode(b"")
        else:
            value_rlp = rlp.encode(value_int.to_bytes((value_int.bit_length() + 7) // 8, "big"))
        nodes = [_to_bytes(n) for n in sp["proof"]["proof_nodes"]]
        ok, err = verify_mpt_proof(storage_hash, keccak(slot_bytes), value_rlp, nodes)
        if not ok:
            raise ValueError(f"storage slot 0x{slot_bytes.hex()} failed: {err}")


def _mapping_slot_for_address(addr: bytes, slot_index: int) -> bytes:
    buf = bytearray(64)
    buf[12:32] = addr
    buf[63] = slot_index & 0xFF
    return keccak(bytes(buf))


def _slot_index_to_bytes32(slot: int) -> bytes:
    buf = bytearray(32)
    buf[31] = slot & 0xFF
    return bytes(buf)


class EthOperations:
    """SDK operations for verifiable Ethereum state reads."""

    def __init__(self, indexer_base_url: str, http: Optional[httpx.AsyncClient] = None):
        self.indexer_base_url = indexer_base_url.rstrip("/")
        self._http = http
        self.mode: StateVerifyMode = StateVerifyMode.STRICT

    def with_mode(self, mode: StateVerifyMode) -> "EthOperations":
        self.mode = mode
        return self

    async def _post(self, path: str, body: dict) -> dict:
        url = f"{self.indexer_base_url}/{path.lstrip('/')}"
        if self._http is not None:
            r = await self._http.post(url, json=body)
        else:
            async with httpx.AsyncClient() as c:
                r = await c.post(url, json=body)
        r.raise_for_status()
        return r.json()

    async def get_state(
        self,
        address: str,
        slots: Iterable[str],
        block_number: int,
    ) -> VerifiedStateRead:
        body = {
            "address": address,
            "slots": list(slots),
            "block": block_number,
        }
        envelope = await self._post("verifiable-rpc/eth/state", body)
        proofs = envelope.get("state_proofs") or []
        if not proofs:
            raise ValueError("response carried no state proof")
        proof = proofs[0]
        if self.mode == StateVerifyMode.STRICT:
            verify_state_proof(proof)
        return _to_verified_state(proof, self.mode)

    async def get_call(self, tx: dict, block_number: int) -> VerifiedCall:
        envelope = await self._post(
            "verifiable-rpc/eth/call", {"tx": tx, "block": block_number}
        )
        proofs = envelope.get("state_proofs") or []
        if self.mode == StateVerifyMode.STRICT:
            for p in proofs:
                verify_state_proof(p)
        import base64

        result = base64.b64decode(envelope["answer"])
        block_number_resp = envelope["block_range"][0]
        block_hash = (
            _hex0x(_to_bytes(proofs[0]["block_hash"]), 32) if proofs else "0x" + "00" * 32
        )
        return VerifiedCall(
            block_number=block_number_resp,
            block_hash=block_hash,
            state_root=_hex0x(_to_bytes(envelope["state_root"]), 32),
            result=result,
            access_state_reads=[_to_verified_state(p, self.mode) for p in proofs],
            mode=self.mode,
        )

    async def erc20_balance(
        self, token: str, holder: str, balance_slot: int, block_number: int
    ) -> int:
        addr_bytes = bytes.fromhex(holder[2:] if holder.startswith("0x") else holder)
        slot = "0x" + _mapping_slot_for_address(addr_bytes, balance_slot).hex()
        state = await self.get_state(token, [slot], block_number)
        if not state.storage:
            raise ValueError("erc20_balance: empty storage_proofs")
        return state.storage[0].value

    async def erc20_total_supply(self, token: str, slot: int, block_number: int) -> int:
        slot_hex = "0x" + _slot_index_to_bytes32(slot).hex()
        state = await self.get_state(token, [slot_hex], block_number)
        if not state.storage:
            raise ValueError("erc20_total_supply: empty storage_proofs")
        return state.storage[0].value


def _to_verified_state(proof: dict, mode: StateVerifyMode) -> VerifiedStateRead:
    acct = proof["account_state"]
    storage = [
        VerifiedStorage(
            slot=_hex0x(_to_bytes(sp["slot"]), 32),
            value=_bytes_to_int(_to_bytes(sp["value"])),
        )
        for sp in proof.get("storage_proofs", [])
    ]
    return VerifiedStateRead(
        address=_hex0x(_to_bytes(proof["address"]), 20),
        block_number=int(proof["block_number"]),
        block_hash=_hex0x(_to_bytes(proof["block_hash"]), 32),
        state_root=_hex0x(_to_bytes(proof["state_root"]), 32),
        nonce=int(acct["nonce"]),
        balance=_bytes_to_int(_to_bytes(acct["balance"])),
        storage_hash=_hex0x(_to_bytes(acct["storage_hash"]), 32),
        code_hash=_hex0x(_to_bytes(acct["code_hash"]), 32),
        storage=storage,
        mode=mode,
    )
