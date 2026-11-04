"""The messages data and file write transactions are signed over: the node's
known answers byte for byte, the line-break refusal, and the consensus
client's transactions verified over the message built from their own fields."""

import json
from pathlib import Path

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from eth_utils import keccak

from willow import (
    delete_file_manifest_message,
    sign_challenge,
    store_data_message,
    store_file_manifest_message,
    verify_signature,
)
from willow.consensus import ConsensusClient, ConsensusConfig
from willow.consensus.types import (
    DataStoreTx,
    DeleteFileManifestTx,
    StoreFileManifestTx,
    create_sign_message,
)

# The node's known answers, unchanged.
KAT = json.loads(
    (Path(__file__).parent / "fixtures" / "signed_messages_kat.json").read_text(encoding="utf-8")
)
SEED = KAT["private_key_seed_hex"]
ED25519_PUBLIC_KEY = KAT["ed25519_public_key_hex"]
SECP256K1_PUBLIC_KEY = KAT["secp256k1_public_key_compressed_hex"]
PUBLIC_KEY_ID = KAT["public_key_id"]

# The kinds this SDK sends. It sends no UpdateData or DeleteData transaction.
SENDABLE = (
    "StoreData",
    "StoreData (non-ASCII, large nonce)",
    "StoreFileManifest",
    "StoreFileManifest (encrypted)",
    "DeleteFileManifest",
)
VECTORS = {v["name"]: v for v in KAT["vectors"]}


def _rfc6979_available() -> bool:
    """Whether the installed `cryptography` signs ECDSA deterministically.

    Without it the SDK signs with a random nonce: still valid, but not equal
    to the known answer."""
    key = ec.derive_private_key(3, ec.SECP256K1())
    try:
        key.sign(b"\x00" * 32, ec.ECDSA(Prehashed(hashes.SHA256()), deterministic_signing=True))
        return True
    except (TypeError, UnsupportedAlgorithm):
        return False


def _encryption(inputs):
    e = inputs["encryption"]
    return None if e is None else (e["key_epoch"], e["nonce_hex"])


def _build(vector) -> str:
    i = vector["inputs"]
    name = vector["name"]
    if name.startswith("StoreData"):
        return store_data_message(
            i["subgrove_id"], i["key"], i["owner_did"], i["data_utf8"].encode("utf-8"), i["nonce"]
        )
    if name.startswith("StoreFileManifest"):
        return store_file_manifest_message(
            i["subgrove_id"],
            i["file_key"],
            i["owner_did"],
            i["filename"],
            i["content_type"],
            i["total_size"],
            bytes.fromhex(i["content_hash_hex"]),
            i["chunk_count"],
            i["chunk_size"],
            bytes.fromhex(i["chunk_merkle_root_hex"]),
            i["nonce"],
            encryption=_encryption(i),
        )
    if name == "DeleteFileManifest":
        return delete_file_manifest_message(i["subgrove_id"], i["file_key"], i["owner_did"], i["nonce"])
    raise AssertionError(f"no builder for {name}")


def _transaction(vector):
    """The SDK transaction for ``vector`` and its ``create_sign_message`` type."""
    i = vector["inputs"]
    name = vector["name"]
    if name.startswith("StoreData"):
        return "DataStore", DataStoreTx(
            subgrove_id=i["subgrove_id"], key=i["key"], data=i["data_utf8"],
            owner_did=i["owner_did"], public_key_id=PUBLIC_KEY_ID, nonce=i["nonce"],
        )
    if name == "StoreFileManifest":
        return name, StoreFileManifestTx(
            subgrove_id=i["subgrove_id"], file_key=i["file_key"], filename=i["filename"],
            content_type=i["content_type"], total_size=i["total_size"],
            content_hash=i["content_hash_hex"], chunk_count=i["chunk_count"],
            chunk_size=i["chunk_size"], chunk_merkle_root=i["chunk_merkle_root_hex"],
            owner_did=i["owner_did"], public_key_id=PUBLIC_KEY_ID, nonce=i["nonce"],
        )
    if name == "DeleteFileManifest":
        return name, DeleteFileManifestTx(
            subgrove_id=i["subgrove_id"], file_key=i["file_key"], owner_did=i["owner_did"],
            public_key_id=PUBLIC_KEY_ID, nonce=i["nonce"],
        )
    raise AssertionError(f"no transaction for {name}")


def test_the_fixture_holds_every_kind_the_sdk_sends():
    assert set(SENDABLE) <= set(VECTORS)
    assert KAT["public_key_id"] == "did:willow:a#key-1"


@pytest.mark.parametrize("name", SENDABLE)
class TestKnownAnswers:
    def test_message(self, name):
        vector = VECTORS[name]
        assert _build(vector).encode("utf-8") == vector["message"].encode("utf-8")

    def test_ed25519_signature(self, name):
        vector = VECTORS[name]
        signature = sign_challenge(_build(vector), SEED, "Ed25519")
        assert signature == vector["ed25519_signature_hex"]
        assert verify_signature(vector["message"], signature, ED25519_PUBLIC_KEY, "Ed25519")

    def test_secp256k1_signs_the_keccak256(self, name):
        vector = VECTORS[name]
        message = _build(vector)
        assert keccak(message.encode("utf-8")).hex() == vector["secp256k1_keccak256_hex"]
        assert verify_signature(
            message, vector["secp256k1_compact_signature_hex"], SECP256K1_PUBLIC_KEY, "secp256k1"
        )
        assert verify_signature(
            message, sign_challenge(message, SEED, "secp256k1"), SECP256K1_PUBLIC_KEY, "secp256k1"
        )

    @pytest.mark.skipif(not _rfc6979_available(), reason="cryptography without RFC 6979 signing")
    def test_secp256k1_signature(self, name):
        vector = VECTORS[name]
        assert sign_challenge(_build(vector), SEED, "secp256k1") == vector["secp256k1_compact_signature_hex"]


# StoreFileManifestTx carries no encryption, so the encrypted vector has no transaction.
@pytest.mark.parametrize("name", [n for n in SENDABLE if n != "StoreFileManifest (encrypted)"])
def test_create_sign_message_is_the_known_answer(name):
    tx_type, tx = _transaction(VECTORS[name])
    assert create_sign_message(tx_type, tx) == VECTORS[name]["message"]


class TestBuilders:
    @pytest.mark.parametrize("name", ["StoreData", "StoreData (non-ASCII, large nonce)"])
    def test_store_data_hashes_the_utf8_of_text(self, name):
        i = VECTORS[name]["inputs"]
        assert store_data_message(
            i["subgrove_id"], i["key"], i["owner_did"], i["data_utf8"], i["nonce"]
        ) == VECTORS[name]["message"]

    def test_text_goes_in_verbatim(self):
        vector = VECTORS["StoreData (non-ASCII, large nonce)"]
        message = _build(vector).encode("utf-8")
        assert b"\nKey: na\xc3\xafve-\xd0\xba\xd0\xbb\xd1\x8e\xd1\x87\n" in message
        assert message.endswith(b"\nNonce: 4294967297")

    def test_manifest_takes_hex_bytes_or_number_lists(self):
        vector = VECTORS["StoreFileManifest (encrypted)"]
        i = vector["inputs"]
        message = store_file_manifest_message(
            i["subgrove_id"], i["file_key"], i["owner_did"], i["filename"], i["content_type"],
            i["total_size"], "0x" + i["content_hash_hex"], i["chunk_count"], i["chunk_size"],
            list(bytes.fromhex(i["chunk_merkle_root_hex"])), i["nonce"],
            encryption=(3, bytes([0xAB]) * 24),
        )
        assert message == vector["message"]

    @pytest.mark.parametrize("bad", [
        dict(content_hash=b"\x11" * 31),
        dict(chunk_merkle_root="22" * 33),
        dict(encryption=(3, b"\xab" * 12)),
        dict(nonce=-1),
        dict(total_size="1048577"),
        dict(chunk_count=True),
        dict(chunk_count=2**32),
        dict(nonce=2**64),
        dict(content_hash=32),
    ])
    def test_manifest_refuses_values_the_transaction_cannot_carry(self, bad):
        args = dict(
            subgrove_id="files-1", file_key="photo.png", owner_did="did:willow:a",
            filename="photo.png", content_type="image/png", total_size=1, content_hash=b"\x11" * 32,
            chunk_count=1, chunk_size=1, chunk_merkle_root=b"\x22" * 32, nonce=1,
        )
        args.update(bad)
        with pytest.raises((ValueError, TypeError)):
            store_file_manifest_message(**args)

    def test_a_new_nonce_is_a_new_message(self):
        assert delete_file_manifest_message("files-1", "photo.png", "did:willow:a", 11) != (
            delete_file_manifest_message("files-1", "photo.png", "did:willow:a", 12)
        )


LINE_BREAK_CASES = [
    (store_data_message, dict(subgrove_id="sg-1", key="doc1", owner_did="did:willow:a", data=b"{}", nonce=1),
     ("subgrove_id", "key", "owner_did")),
    (store_file_manifest_message, dict(
        subgrove_id="files-1", file_key="photo.png", owner_did="did:willow:a", filename="photo.png",
        content_type="image/png", total_size=1, content_hash=b"\x11" * 32, chunk_count=1,
        chunk_size=1, chunk_merkle_root=b"\x22" * 32, nonce=1,
    ), ("subgrove_id", "file_key", "owner_did", "filename", "content_type")),
    (delete_file_manifest_message, dict(subgrove_id="files-1", file_key="photo.png", owner_did="did:willow:a", nonce=1),
     ("subgrove_id", "file_key", "owner_did")),
]


@pytest.mark.parametrize(
    "builder,args,field",
    [(b, a, f) for b, a, fields in LINE_BREAK_CASES for f in fields],
    ids=[f"{b.__name__}-{f}" for b, _, fields in LINE_BREAK_CASES for f in fields],
)
def test_a_text_field_with_a_line_break_is_refused(builder, args, field):
    builder(**args)
    for value in ("a\nb", "\n", "trailing\n", "a\r\nb"):
        with pytest.raises(ValueError, match="line break"):
            builder(**dict(args, **{field: value}))
    # Only the byte 0x0A is a line break, as the node reads it.
    for value in ("a\rb", "a\u2028b", "a\u0085b"):
        assert f": {value}\n" in builder(**dict(args, **{field: value}))


def test_create_sign_message_refuses_a_line_break():
    tx_type, tx = _transaction(VECTORS["StoreData"])
    tx.key = "doc1\nNonce: 99"
    with pytest.raises(ValueError, match="line break"):
        create_sign_message(tx_type, tx)


# ---------------------------------------------------------------------------
# The consensus client, through a fake session: each transaction it sends to
# /tx/submit verified over the message built from its own fields.
# ---------------------------------------------------------------------------


class _Response:
    def __init__(self, payload):
        self.status = 200
        self._payload = payload

    async def json(self, content_type="application/json"):
        return self._payload

    async def text(self):
        return json.dumps(self._payload)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _Session:
    """Answers the account nonce with ``nonce`` and accepts every transaction."""

    def __init__(self, nonce):
        self.nonce = nonce
        self.submitted = []

    def get(self, url):
        assert url.endswith("/nonce")
        return _Response({"success": True, "data": {"nonce": self.nonce}})

    def post(self, url, json):
        assert url == "http://api.test/tx/submit"
        self.submitted.append(json)
        return _Response({"success": True, "data": {"tx_hash": "AB", "code": 0, "log": ""}})


def _consensus_client(account_nonce):
    client = ConsensusClient(ConsensusConfig(consensus_rpc_url="http://rpc.test", api_url="http://api.test"))
    client._session = _Session(account_nonce)
    return client


def _only_submitted(client, kind):
    (tx,) = client._session.submitted
    assert list(tx) == [kind]
    return tx[kind]


def _verifies(message, body, algorithm):
    public_key = ED25519_PUBLIC_KEY if algorithm == "Ed25519" else SECP256K1_PUBLIC_KEY
    return verify_signature(message, bytes(body["signature"]).hex(), public_key, algorithm)


@pytest.mark.asyncio
@pytest.mark.parametrize("algorithm", ["Ed25519", "secp256k1"])
async def test_store_data_signs_the_transaction_it_sends(algorithm):
    vector = VECTORS["StoreData"]
    i = vector["inputs"]
    client = _consensus_client(i["nonce"] - 1)
    result = await client.store_data(
        i["subgrove_id"], i["key"], {"value": 42, "title": "Hello"}, i["owner_did"],
        SEED, PUBLIC_KEY_ID, algorithm,
    )
    assert result.success

    body = _only_submitted(client, "StoreData")
    # The chain's StoreData, with data as the JSON text's UTF-8 bytes.
    assert body["data"] == list(i["data_utf8"].encode("utf-8"))
    assert body["nonce"] == i["nonce"]
    message = store_data_message(
        body["subgrove_id"], body["key"], body["owner_did"], bytes(body["data"]), body["nonce"]
    )
    assert message == vector["message"]
    assert _verifies(message, body, algorithm)
    if algorithm == "Ed25519":
        assert bytes(body["signature"]).hex() == vector["ed25519_signature_hex"]
    elif _rfc6979_available():
        assert bytes(body["signature"]).hex() == vector["secp256k1_compact_signature_hex"]


@pytest.mark.asyncio
@pytest.mark.parametrize("algorithm", ["Ed25519", "secp256k1"])
async def test_store_file_manifest_signs_the_transaction_it_sends(algorithm):
    vector = VECTORS["StoreFileManifest"]
    i = vector["inputs"]
    client = _consensus_client(i["nonce"] - 1)
    await client.store_file_manifest(
        i["subgrove_id"], i["file_key"], i["filename"], i["content_type"], i["total_size"],
        i["content_hash_hex"], i["chunk_count"], i["chunk_size"], i["chunk_merkle_root_hex"],
        i["owner_did"], SEED, PUBLIC_KEY_ID, algorithm,
    )

    body = _only_submitted(client, "StoreFileManifest")
    assert body["content_hash"] == list(bytes.fromhex(i["content_hash_hex"]))
    assert body["chunk_merkle_root"] == list(bytes.fromhex(i["chunk_merkle_root_hex"]))
    assert "encryption" not in body
    message = store_file_manifest_message(
        body["subgrove_id"], body["file_key"], body["owner_did"], body["filename"],
        body["content_type"], body["total_size"], body["content_hash"], body["chunk_count"],
        body["chunk_size"], body["chunk_merkle_root"], body["nonce"],
    )
    assert message == vector["message"]
    assert _verifies(message, body, algorithm)
    if algorithm == "Ed25519":
        assert bytes(body["signature"]).hex() == vector["ed25519_signature_hex"]


@pytest.mark.asyncio
@pytest.mark.parametrize("algorithm", ["Ed25519", "secp256k1"])
async def test_delete_file_manifest_signs_the_transaction_it_sends(algorithm):
    vector = VECTORS["DeleteFileManifest"]
    i = vector["inputs"]
    client = _consensus_client(i["nonce"] - 1)
    await client.delete_file_manifest(
        i["subgrove_id"], i["file_key"], i["owner_did"], SEED, PUBLIC_KEY_ID, algorithm
    )

    body = _only_submitted(client, "DeleteFileManifest")
    message = delete_file_manifest_message(
        body["subgrove_id"], body["file_key"], body["owner_did"], body["nonce"]
    )
    assert message == vector["message"]
    assert _verifies(message, body, algorithm)
    if algorithm == "Ed25519":
        assert bytes(body["signature"]).hex() == vector["ed25519_signature_hex"]


@pytest.mark.asyncio
async def test_the_next_nonce_is_signed():
    vector = VECTORS["DeleteFileManifest"]
    i = vector["inputs"]
    client = _consensus_client(i["nonce"])
    await client.delete_file_manifest(i["subgrove_id"], i["file_key"], i["owner_did"], SEED, PUBLIC_KEY_ID)

    body = _only_submitted(client, "DeleteFileManifest")
    assert body["nonce"] == i["nonce"] + 1
    assert not _verifies(vector["message"], body, "Ed25519")
    assert _verifies(
        delete_file_manifest_message(i["subgrove_id"], i["file_key"], i["owner_did"], i["nonce"] + 1),
        body, "Ed25519",
    )


@pytest.mark.asyncio
async def test_store_data_signs_non_ascii_text_and_a_large_nonce_as_sent():
    vector = VECTORS["StoreData (non-ASCII, large nonce)"]
    i = vector["inputs"]
    client = _consensus_client(i["nonce"] - 1)
    await client.store_data(
        i["subgrove_id"], i["key"], json.loads(i["data_utf8"]), i["owner_did"], SEED, PUBLIC_KEY_ID
    )

    body = _only_submitted(client, "StoreData")
    assert (body["key"], body["nonce"]) == (i["key"], i["nonce"])
    message = store_data_message(
        body["subgrove_id"], body["key"], body["owner_did"], bytes(body["data"]), body["nonce"]
    )
    assert _verifies(message, body, "Ed25519")
    # The hash is over the data bytes sent: json.dumps escapes non-ASCII.
    assert bytes(body["data"]) == b'{"msg":"h\\u00e9llo \\u4e16\\u754c"}'
    sent_tx_type, sent_tx = _transaction(vector)
    sent_tx.data = bytes(body["data"]).decode("utf-8")
    assert create_sign_message(sent_tx_type, sent_tx) == message


@pytest.mark.asyncio
async def test_store_data_with_a_line_break_is_not_sent():
    client = _consensus_client(0)
    with pytest.raises(ValueError, match="line break"):
        await client.store_data("sg-1", "doc1\n", {}, "did:willow:a", SEED, PUBLIC_KEY_ID)
    assert client._session.submitted == []
