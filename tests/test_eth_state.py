"""Unit tests for the verifiable Ethereum state-read module."""

import pytest
import rlp
from eth_hash.auto import keccak

from willow.eth_state import (
    StateVerifyMode,
    verify_mpt_proof,
    verify_state_proof,
)


def test_mpt_rejects_short_root():
    ok, err = verify_mpt_proof(b"\x00" * 16, b"\x00" * 32, b"", [b"\xc0"])
    assert not ok
    assert "root must be 32 bytes" in err


def test_mpt_rejects_empty_proof():
    ok, err = verify_mpt_proof(b"\x00" * 32, b"\x00" * 32, b"", [])
    assert not ok
    assert "empty" in err


def test_mpt_rejects_mismatched_root_hash():
    ok, err = verify_mpt_proof(b"\x00" * 32, b"\x00" * 32, b"\x80", [b"\xc0"])
    assert not ok
    assert "hash mismatch" in err


def test_mpt_verifies_single_leaf_trie():
    """End-to-end smoke: build a tiny one-leaf trie and verify it."""
    key_hash = keccak(b"hello")
    # Compact-encoded leaf path: 0x20 prefix (leaf, even nibble count) + full key.
    encoded_path = bytes([0x20]) + key_hash
    value = b"\xab\xcd\xef"
    leaf_node = rlp.encode([encoded_path, value])
    root = keccak(leaf_node)
    ok, err = verify_mpt_proof(root, key_hash, value, [leaf_node])
    assert ok, f"verifier rejected valid leaf: {err}"


def test_verify_state_proof_rejects_tampered_balance():
    proof = {
        "address": [0] * 20,
        "block_number": 1,
        "block_hash": [0] * 32,
        "state_root": [0] * 32,
        "account_proof": {
            "key": [0] * 32,
            "value": [],
            "proof_nodes": [],
        },
        "account_state": {
            "nonce": 0,
            "balance": [0xFF] * 32,  # tampered
            "storage_hash": [0] * 32,
            "code_hash": [0] * 32,
        },
        "storage_proofs": [],
    }
    with pytest.raises(ValueError):
        verify_state_proof(proof)
