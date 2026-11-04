"""The second signed set: registrations, key grants, and storage-node removals.

The node's known answers byte for byte (messages, RegisterSubgrove bincode,
and signatures), the line-break and range refusals, and each flow's
transaction verified over the message built from its own fields."""

import copy
import json
from pathlib import Path

import httpx
import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from eth_utils import keccak

from willow import (
    CommitmentFrequency,
    EncryptedKeyGrant,
    PrivacyConfig,
    WillowClient,
    grant_subgrove_key_message,
    normalize_register_subgrove,
    register_subgrove_message,
    register_subgrove_unsigned_bincode,
    revoke_subgrove_key_message,
    rotate_subgrove_key_message,
    sign_challenge,
    unregister_storage_node_message,
    verify_signature,
)
from willow.consensus import ConsensusClient, ConsensusConfig
from willow.consensus.types import (
    GrantSubgroveKeyTx,
    RegisterSubgroveTx,
    RetentionWindow,
    RotateSubgroveKeyTx,
    create_sign_message,
)
from willow.errors import TransactionError

FIXTURES = Path(__file__).parent / "fixtures"
KAT = json.loads((FIXTURES / "signed_messages_kat_2.json").read_text(encoding="utf-8"))
SEED = KAT["private_key_seed_hex"]
ED25519_PUBLIC_KEY = KAT["ed25519_public_key_hex"]
SECP256K1_PUBLIC_KEY = KAT["secp256k1_public_key_compressed_hex"]
PUBLIC_KEY_ID = KAT["public_key_id"]
VECTORS = {v["name"]: v for v in KAT["vectors"]}

# The kinds this SDK sends. It builds no UpdateSubgroveReadPricing,
# BlockContentHash, UnblockContentHash, or ReportContent transaction.
SENDABLE = (
    "RegisterSubgrove (data)",
    "RegisterSubgrove (data, defaults)",
    "RegisterSubgrove (file)",
    "RegisterSubgrove (private, non-ASCII, large nonce)",
    "RegisterSubgrove (indexing)",
    "GrantSubgroveKey",
    "RotateSubgroveKey",
    "UnregisterStorageNode",
)
NOT_SENT = (
    "UpdateSubgroveReadPricing",
    "UpdateSubgroveReadPricing (none)",
    "BlockContentHash",
    "UnblockContentHash",
    "ReportContent",
)


def _rfc6979_available() -> bool:
    key = ec.derive_private_key(3, ec.SECP256K1())
    try:
        key.sign(b"\x00" * 32, ec.ECDSA(Prehashed(hashes.SHA256()), deterministic_signing=True))
        return True
    except (TypeError, UnsupportedAlgorithm):
        return False


def _transaction(name):
    """The vector's kind and transaction object, parsed exactly (Python ints
    keep every u64 and u128 whole)."""
    ((kind, tx),) = json.loads(VECTORS[name]["transaction_json"]).items()
    return kind, tx


def _build(name) -> str:
    """The vector's message, from the SDK's public builder for its kind."""
    kind, t = _transaction(name)
    if kind == "RegisterSubgrove":
        return register_subgrove_message(t)
    if kind == "GrantSubgroveKey":
        return grant_subgrove_key_message(t["subgrove_id"], t["sender_did"], t["encrypted_key_grant"], t["nonce"])
    if kind == "RotateSubgroveKey":
        return rotate_subgrove_key_message(
            t["subgrove_id"], t["sender_did"], t["new_epoch"], t["new_grants"], t["nonce"]
        )
    if kind == "UnregisterStorageNode":
        return unregister_storage_node_message(t["node_did"], t["nonce"])
    raise AssertionError(f"no builder for {name}")


def test_the_fixture_holds_every_kind_the_sdk_sends():
    assert set(SENDABLE) | set(NOT_SENT) == set(VECTORS)
    assert PUBLIC_KEY_ID == "did:willow:a#key-1"


@pytest.mark.parametrize("name", SENDABLE)
class TestKnownAnswers:
    def test_message(self, name):
        assert _build(name).encode("utf-8") == VECTORS[name]["message"].encode("utf-8")

    def test_ed25519_signature(self, name):
        vector = VECTORS[name]
        signature = sign_challenge(_build(name), SEED, "Ed25519")
        assert signature == vector["ed25519_signature_hex"]
        assert verify_signature(vector["message"], signature, ED25519_PUBLIC_KEY, "Ed25519")

    def test_secp256k1_signs_the_keccak256(self, name):
        vector = VECTORS[name]
        message = _build(name)
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
        assert sign_challenge(_build(name), SEED, "secp256k1") == vector["secp256k1_compact_signature_hex"]


REGISTRATIONS = [n for n in SENDABLE if n.startswith("RegisterSubgrove")]


@pytest.mark.parametrize("name", REGISTRATIONS)
def test_register_subgrove_bincode_is_the_known_answer(name):
    _, tx = _transaction(name)
    assert register_subgrove_unsigned_bincode(tx).hex() == VECTORS[name]["unsigned_bincode_hex"]


@pytest.mark.parametrize("name", REGISTRATIONS)
def test_a_complete_registration_normalizes_to_itself(name):
    # Every field of the known answers is explicit and in the node's order.
    _, tx = _transaction(name)
    normalized = normalize_register_subgrove(tx)
    assert normalized == tx
    assert list(normalized) == list(tx)


def test_the_bincode_ignores_the_signature():
    _, tx = _transaction("RegisterSubgrove (data)")
    signed = dict(tx, signature=list(range(64)))
    assert register_subgrove_unsigned_bincode(signed).hex() == VECTORS["RegisterSubgrove (data)"]["unsigned_bincode_hex"]


def test_omitted_fields_take_the_nodes_values():
    name = "RegisterSubgrove (data, defaults)"
    _, tx = _transaction(name)
    sparse = {k: tx[k] for k in ("subgrove_id", "name", "schema", "owner_did", "signature", "public_key_id", "nonce")}
    assert normalize_register_subgrove(sparse) == tx
    assert register_subgrove_message(sparse) == VECTORS[name]["message"]

    _, indexing = _transaction("RegisterSubgrove (indexing)")
    mode = indexing["mode"]["BlockchainIndexing"]
    bare = dict(indexing, mode={"BlockchainIndexing": {
        k: mode[k] for k in ("manifest_content", "execution_mode", "indexer_config")
    }})
    explicit = normalize_register_subgrove(bare)["mode"]["BlockchainIndexing"]
    assert explicit["wasm_modules"] == []
    assert explicit["retention_window"] == "Indefinite"
    assert explicit["completeness"] is None
    assert explicit["historical_auth_mode"] == "BftEquivalent"


def test_registration_takes_bytes_hex_and_number_text():
    name = "RegisterSubgrove (indexing)"
    _, tx = _transaction(name)
    mode = copy.deepcopy(tx["mode"])
    m = mode["BlockchainIndexing"]
    m["manifest_content"] = bytes(m["manifest_content"])
    m["wasm_modules"][0]["hash"] = "0x" + bytes(m["wasm_modules"][0]["hash"]).hex()
    m["indexer_config"]["min_indexer_stake"] = str(m["indexer_config"]["min_indexer_stake"])
    m["retention_window"] = RetentionWindow(type="Blocks", value=1000)
    assert register_subgrove_message(dict(tx, mode=mode)) == VECTORS[name]["message"]


@pytest.mark.parametrize("change", [
    lambda t: t.pop("name"),
    lambda t: t.pop("schema"),
    lambda t: t.pop("nonce"),
    lambda t: t.update(nonce=2**64),
    lambda t: t.update(nonce=-1),
    lambda t: t.update(confirmation_depth=2**32),
    lambda t: t.update(initial_funding=2**128),
    lambda t: t.update(initial_funding=1.5),
    lambda t: t.update(cryptographic_completeness=1),
    lambda t: t.update(admins="did:willow:b"),
    lambda t: t.update(mode={"KeyValue": {}}),
    lambda t: t.update(mode={"FileStorage": {"name": "f", "replication_factor": 3, "writers": [], "free_readers": []}}),
    lambda t: t.update(mode={"DataStorage": {"name": "n", "writers": [], "free_readers": [], "readers": []}}),
    lambda t: t["mode"]["DataStorage"]["read_pricing"].update(owner_revenue_share_bps=2**32),
    lambda t: t.update(checkpoint_verification={"required_tee": "Enclave"}),
])
def test_registration_refuses_what_the_node_cannot_decode(change):
    _, tx = _transaction("RegisterSubgrove (data)")
    change(tx)
    with pytest.raises((ValueError, TypeError)):
        register_subgrove_message(tx)


def test_every_mode_encodes():
    # The SDK encodes every mode, BlockchainIndexing with WASM modules,
    # completeness, and a template included, so it refuses none.
    kinds = {next(iter(_transaction(n)[1]["mode"])) for n in REGISTRATIONS}
    assert kinds == {"DataStorage", "FileStorage", "BlockchainIndexing"}


# ---------------------------------------------------------------------------
# Line breaks: refused in every field a message writes out.
# ---------------------------------------------------------------------------


def _grant():
    return _transaction("GrantSubgroveKey")[1]["encrypted_key_grant"]


LINE_BREAK_CASES = [
    # An indexing subgrove: a data or file subgrove's ID takes no '\r', ' ', or ':' either.
    ("RegisterSubgrove subgrove_id", lambda v: register_subgrove_message(dict(_transaction("RegisterSubgrove (indexing)")[1], subgrove_id=v))),
    ("RegisterSubgrove owner_did", lambda v: register_subgrove_message(dict(_transaction("RegisterSubgrove (data)")[1], owner_did=v))),
    ("GrantSubgroveKey subgrove_id", lambda v: grant_subgrove_key_message(v, "did:willow:a", _grant(), 1)),
    ("GrantSubgroveKey sender_did", lambda v: grant_subgrove_key_message("sg", v, _grant(), 1)),
    ("GrantSubgroveKey grantee_did", lambda v: grant_subgrove_key_message("sg", "did:willow:a", dict(_grant(), grantee_did=v), 1)),
    ("GrantSubgroveKey grantee_public_key_id", lambda v: grant_subgrove_key_message("sg", "did:willow:a", dict(_grant(), grantee_public_key_id=v), 1)),
    ("GrantSubgroveKey granted_by", lambda v: grant_subgrove_key_message("sg", "did:willow:a", dict(_grant(), granted_by=v), 1)),
    ("RotateSubgroveKey subgrove_id", lambda v: rotate_subgrove_key_message(v, "did:willow:a", 1, [_grant()], 1)),
    ("RotateSubgroveKey sender_did", lambda v: rotate_subgrove_key_message("sg", v, 1, [_grant()], 1)),
    ("RotateSubgroveKey grantee_did", lambda v: rotate_subgrove_key_message("sg", "did:willow:a", 1, [_grant(), dict(_grant(), grantee_did=v)], 1)),
    ("UnregisterStorageNode node_did", lambda v: unregister_storage_node_message(v, 1)),
]


@pytest.mark.parametrize("build", [b for _, b in LINE_BREAK_CASES], ids=[n for n, _ in LINE_BREAK_CASES])
def test_a_text_field_with_a_line_break_is_refused(build):
    build("did:willow:x")
    for value in ("a\nb", "\n", "trailing\n", "a\r\nb"):
        with pytest.raises(ValueError, match="line break"):
            build(value)
    for value in ("a\rb", "a b"):
        build(value)


def test_registration_text_hashed_into_config_may_hold_a_line_break():
    # Only Subgrove and Owner are lines; the rest is bound by Config.
    _, tx = _transaction("RegisterSubgrove (data)")
    message = register_subgrove_message(dict(tx, description="two\nlines"))
    assert message != VECTORS["RegisterSubgrove (data)"]["message"]


def test_grant_fields_are_range_checked():
    for bad in (dict(key_epoch=2**32), dict(granted_at=2**64), dict(encrypted_key="zz"), dict(ephemeral_public_key=[256])):
        with pytest.raises((ValueError, TypeError)):
            grant_subgrove_key_message("sg", "did:willow:a", dict(_grant(), **bad), 1)
    with pytest.raises(ValueError):
        rotate_subgrove_key_message("sg", "did:willow:a", 2**32, [], 1)


def test_revoke_keeps_the_nodes_message():
    assert revoke_subgrove_key_message("private-1", "did:willow:b", "did:willow:a", 4294967297) == (
        "RevokeSubgroveKey:private-1:did:willow:b:did:willow:a:4294967297"
    )


def test_a_new_nonce_is_a_new_message():
    assert unregister_storage_node_message("did:willow:a", 14) != unregister_storage_node_message("did:willow:a", 15)


# ---------------------------------------------------------------------------
# The SDK's transaction objects build the same messages.
# ---------------------------------------------------------------------------


def _register_subgrove_tx(t) -> RegisterSubgroveTx:
    return RegisterSubgroveTx(
        subgrove_id=t["subgrove_id"], schema=t["schema"], owner_did=t["owner_did"], mode=t["mode"],
        public_key_id=t["public_key_id"], nonce=t["nonce"], name=t["name"],
        description=t["description"], admins=t["admins"], initial_funding=t["initial_funding"],
        required_tee=t["checkpoint_verification"]["required_tee"], privacy=t["privacy"],
        initial_owner_key_grant=t["initial_owner_key_grant"], template_config=t["template_config"],
        confirmation_depth=t["confirmation_depth"],
        cryptographic_completeness=t["cryptographic_completeness"],
    )


@pytest.mark.parametrize("name", REGISTRATIONS)
def test_register_subgrove_tx_is_the_known_answer(name):
    _, t = _transaction(name)
    tx = _register_subgrove_tx(t)
    assert tx.to_dict() == t
    assert create_sign_message("RegisterSubgrove", tx) == VECTORS[name]["message"]


def test_register_subgrove_tx_takes_its_name_from_the_mode():
    _, t = _transaction("RegisterSubgrove (data)")
    tx = _register_subgrove_tx(t)
    tx.name = None
    assert tx.to_dict()["name"] == "Notes"
    assert create_sign_message("RegisterSubgrove", tx) == VECTORS["RegisterSubgrove (data)"]["message"]


def test_register_subgrove_tx_puts_retention_window_in_the_indexing_mode():
    _, t = _transaction("RegisterSubgrove (indexing)")
    tx = _register_subgrove_tx(t)
    indexing = dict(t["mode"]["BlockchainIndexing"])
    del indexing["retention_window"]
    tx.mode = {"BlockchainIndexing": indexing}
    tx.retention_window = RetentionWindow(type="Blocks", value=1000)
    assert create_sign_message("RegisterSubgrove", tx) == VECTORS["RegisterSubgrove (indexing)"]["message"]

    data_tx = _register_subgrove_tx(_transaction("RegisterSubgrove (data)")[1])
    data_tx.retention_window = RetentionWindow(type="Blocks", value=1000)
    with pytest.raises(ValueError, match="BlockchainIndexing"):
        data_tx.to_dict()


def test_key_grant_txs_are_the_known_answers():
    _, g = _transaction("GrantSubgroveKey")
    grant = GrantSubgroveKeyTx(
        subgrove_id=g["subgrove_id"], encrypted_key_grant=g["encrypted_key_grant"],
        sender_did=g["sender_did"], public_key_id=g["public_key_id"], nonce=g["nonce"],
    )
    assert create_sign_message("GrantSubgroveKey", grant) == VECTORS["GrantSubgroveKey"]["message"]
    _, r = _transaction("RotateSubgroveKey")
    rotate = RotateSubgroveKeyTx(
        subgrove_id=r["subgrove_id"], new_epoch=r["new_epoch"], new_grants=r["new_grants"],
        sender_did=r["sender_did"], public_key_id=r["public_key_id"], nonce=r["nonce"],
    )
    assert create_sign_message("RotateSubgroveKey", rotate) == VECTORS["RotateSubgroveKey"]["message"]


# ---------------------------------------------------------------------------
# Flows, through mocked transports: each transaction sent carries a signature
# that verifies over the message built from its own fields.
# ---------------------------------------------------------------------------


def _verifies(message, body, algorithm="Ed25519"):
    public_key = ED25519_PUBLIC_KEY if algorithm == "Ed25519" else SECP256K1_PUBLIC_KEY
    return verify_signature(message, bytes(body["signature"]).hex(), public_key, algorithm)


def _expect_signed(name, body, algorithm="Ed25519"):
    """``body`` is the vector's transaction, signed with the vector's signature."""
    vector = VECTORS[name]
    _, expected = _transaction(name)
    assert {k: v for k, v in body.items() if k != "signature"} == {
        k: v for k, v in expected.items() if k != "signature"
    }
    assert _verifies(vector["message"], body, algorithm)
    if algorithm == "Ed25519":
        assert bytes(body["signature"]).hex() == vector["ed25519_signature_hex"]
    elif _rfc6979_available():
        assert bytes(body["signature"]).hex() == vector["secp256k1_compact_signature_hex"]


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
        self.read_nonces = 0
        self.submitted = []

    def get(self, url):
        assert url.endswith("/nonce")
        self.read_nonces += 1
        return _Response({"success": True, "data": {"nonce": self.nonce}})

    def post(self, url, json):
        assert url == "http://api.test/tx/submit"
        self.submitted.append(_as_sent(json))
        return _Response({"success": True, "data": {"tx_hash": "AB", "code": 0, "log": ""}})


def _as_sent(value):
    """``value`` as the session sends it: its JSON text, read back."""
    return json.loads(json.dumps(value))


def _consensus_client(account_nonce):
    client = ConsensusClient(ConsensusConfig(consensus_rpc_url="http://rpc.test", api_url="http://api.test"))
    client._session = _Session(account_nonce)
    return client


def _only_submitted(client, kind):
    (tx,) = client._session.submitted
    assert list(tx) == [kind]
    return tx[kind]


@pytest.mark.asyncio
@pytest.mark.parametrize("algorithm", ["Ed25519", "secp256k1"])
async def test_consensus_register_subgrove_sends_and_signs_every_field(algorithm):
    name = "RegisterSubgrove (data)"
    _, t = _transaction(name)
    client = _consensus_client(t["nonce"] - 1)
    result = await client.register_subgrove(
        t["subgrove_id"], t["schema"], t["owner_did"], SEED, PUBLIC_KEY_ID, t["mode"], algorithm,
        description=t["description"], admins=t["admins"], initial_funding=t["initial_funding"],
    )
    assert result.success
    body = _only_submitted(client, "RegisterSubgrove")
    assert register_subgrove_message(body) == VECTORS[name]["message"]
    _expect_signed(name, body, algorithm)


@pytest.mark.asyncio
async def test_consensus_register_subgrove_with_sdk_privacy_and_grant_objects():
    name = "RegisterSubgrove (private, non-ASCII, large nonce)"
    _, t = _transaction(name)
    g = t["initial_owner_key_grant"]
    client = _consensus_client(t["nonce"] - 1)
    await client.register_subgrove(
        t["subgrove_id"], t["schema"], t["owner_did"], SEED, PUBLIC_KEY_ID, t["mode"],
        description=t["description"],
        privacy=PrivacyConfig(
            allowed_indexers=["did:willow:idx"], commitment_frequency=CommitmentFrequency.every_n_blocks(100)
        ),
        initial_owner_key_grant=EncryptedKeyGrant(
            grantee_did=g["grantee_did"], key_epoch=g["key_epoch"],
            grantee_public_key_id=g["grantee_public_key_id"],
            ephemeral_public_key=bytes(g["ephemeral_public_key"]).hex(),
            encrypted_key=bytes(g["encrypted_key"]),
            granted_by=g["granted_by"], granted_at=g["granted_at"],
        ),
        confirmation_depth=t["confirmation_depth"],
    )
    _expect_signed(name, _only_submitted(client, "RegisterSubgrove"))


@pytest.mark.asyncio
async def test_consensus_register_subgrove_indexing_mode():
    name = "RegisterSubgrove (indexing)"
    _, t = _transaction(name)
    mode = copy.deepcopy(t["mode"])
    mode["BlockchainIndexing"]["manifest_content"] = bytes(mode["BlockchainIndexing"]["manifest_content"])
    client = _consensus_client(t["nonce"] - 1)
    await client.register_subgrove(
        t["subgrove_id"], t["schema"], t["owner_did"], SEED, PUBLIC_KEY_ID, mode,
        name=t["name"], description=t["description"], required_tee="AwsNitro",
        template_config=t["template_config"], cryptographic_completeness=True,
    )
    _expect_signed(name, _only_submitted(client, "RegisterSubgrove"))


@pytest.mark.asyncio
async def test_consensus_register_subgrove_refused_before_anything_is_sent():
    client = _consensus_client(0)
    with pytest.raises(ValueError, match="line break"):
        await client.register_subgrove("sg\n", "{}", "did:willow:a", SEED, PUBLIC_KEY_ID)
    with pytest.raises(ValueError, match="max_file_size"):
        await client.register_subgrove(
            "sg", "{}", "did:willow:a", SEED, PUBLIC_KEY_ID,
            {"FileStorage": {"name": "f", "replication_factor": 3, "writers": [], "free_readers": []}},
        )
    assert client._session.submitted == []
    assert client._session.read_nonces == 0


@pytest.mark.asyncio
async def test_consensus_store_data_refuses_a_non_object():
    client = _consensus_client(0)
    with pytest.raises(TypeError, match="JSON object"):
        await client.store_data("sg-1", "doc1", ["not", "an", "object"], "did:willow:a", SEED, PUBLIC_KEY_ID)
    assert client._session.submitted == []


@pytest.mark.asyncio
async def test_consensus_submit_reports_a_plain_text_refusal():
    class PlainText(_Response):
        def __init__(self):
            self.status = 422

        async def json(self, content_type="application/json"):
            raise ValueError("not JSON")

        async def text(self):
            return "Failed to deserialize the JSON body into the target type: missing field `name`"

    client = _consensus_client(0)
    client._session.post = lambda url, json: PlainText()
    result = await client._broadcast_transaction({"StoreData": {}})
    assert not result.success
    assert "missing field `name`" in result.error_message


def _api(account_nonce, seen, code=0):
    """A mocked API: the account nonce, and /tx/submit answering ``code``."""

    def handler(request):
        seen.append(request)
        if request.url.path.endswith("/nonce"):
            data = {"did": "did:willow:a", "nonce": account_nonce}
        elif request.url.path == "/tx/submit":
            data = {"tx_hash": "AB", "code": code, "log": "" if code == 0 else "refused"}
        else:
            raise AssertionError(f"unexpected {request.url.path}")
        return httpx.Response(200, json={"success": True, "data": data, "error": None})

    return handler


def _willow_client(account_nonce, algorithm="Ed25519", code=0):
    seen = []
    client = WillowClient("http://api.test")
    client._http = httpx.AsyncClient(transport=httpx.MockTransport(_api(account_nonce, seen, code)))
    client.set_identity("did:willow:a", SEED, PUBLIC_KEY_ID, algorithm)
    return client, seen


def _sent(seen, kind):
    (submit,) = [r for r in seen if r.url.path == "/tx/submit"]
    tx = json.loads(submit.content)
    assert list(tx) == [kind]
    return tx[kind]


@pytest.mark.asyncio
@pytest.mark.parametrize("algorithm", ["Ed25519", "secp256k1"])
async def test_grant_subgrove_key_sends_and_signs_every_field(algorithm):
    name = "GrantSubgroveKey"
    _, t = _transaction(name)
    g = t["encrypted_key_grant"]
    client, seen = _willow_client(t["nonce"] - 1, algorithm)
    # The grant as the SDK's type, byte fields as hex.
    grant = EncryptedKeyGrant(
        grantee_did=g["grantee_did"], key_epoch=g["key_epoch"],
        grantee_public_key_id=g["grantee_public_key_id"],
        ephemeral_public_key=bytes(g["ephemeral_public_key"]).hex(),
        encrypted_key=bytes(g["encrypted_key"]).hex(),
        granted_by=g["granted_by"], granted_at=g["granted_at"],
    )
    result = await client.privacy.grant_subgrove_key(t["subgrove_id"], grant)
    assert result["tx_hash"] == "AB"
    assert [(r.method, r.url.path) for r in seen] == [
        ("GET", "/account/did:willow:a/nonce"), ("POST", "/tx/submit"),
    ]
    body = _sent(seen, name)
    assert grant_subgrove_key_message(
        body["subgrove_id"], body["sender_did"], body["encrypted_key_grant"], body["nonce"]
    ) == VECTORS[name]["message"]
    _expect_signed(name, body, algorithm)
    await client.close()


@pytest.mark.asyncio
async def test_rotate_subgrove_key_sends_and_signs_every_grant():
    name = "RotateSubgroveKey"
    _, t = _transaction(name)
    client, seen = _willow_client(t["nonce"] - 1)
    grants = [EncryptedKeyGrant.from_dict(g) for g in t["new_grants"]]  # as the API answers them
    await client.privacy.rotate_subgrove_key(t["subgrove_id"], t["new_epoch"], grants)
    body = _sent(seen, name)
    assert rotate_subgrove_key_message(
        body["subgrove_id"], body["sender_did"], body["new_epoch"], body["new_grants"], body["nonce"]
    ) == VECTORS[name]["message"]
    _expect_signed(name, body)
    await client.close()


@pytest.mark.asyncio
async def test_revoke_subgrove_key_sends_a_signed_transaction():
    client, seen = _willow_client(4294967296)
    await client.privacy.revoke_subgrove_key("private-1", "did:willow:b")
    body = _sent(seen, "RevokeSubgroveKey")
    assert body == {
        "subgrove_id": "private-1", "revokee_did": "did:willow:b", "sender_did": "did:willow:a",
        "signature": body["signature"], "public_key_id": PUBLIC_KEY_ID, "nonce": 4294967297,
    }
    message = revoke_subgrove_key_message(
        body["subgrove_id"], body["revokee_did"], body["sender_did"], body["nonce"]
    )
    assert _verifies(message, body)
    await client.close()


@pytest.mark.asyncio
async def test_a_grant_with_a_line_break_is_not_sent():
    client, seen = _willow_client(0)
    grant = dict(_grant(), grantee_did="did:willow:b\nNonce: 1")
    with pytest.raises(ValueError, match="line break"):
        await client.privacy.grant_subgrove_key("private-1", grant)
    assert seen == []
    await client.close()


@pytest.mark.asyncio
async def test_a_grant_refused_by_checktx_raises():
    client, _ = _willow_client(0, code=7)
    with pytest.raises(TransactionError) as exc_info:
        await client.privacy.grant_subgrove_key("private-1", _grant())
    assert exc_info.value.error_code == 7
    await client.close()


@pytest.fixture
def file_tx_submit(monkeypatch):
    """Route the file client's httpx.AsyncClient through a mocked /tx/submit."""
    requests = []
    real_async_client = httpx.AsyncClient

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"success": True, "data": {"tx_hash": "AB", "code": 0, "log": ""}, "error": None})

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_async_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return requests


@pytest.mark.asyncio
async def test_unregister_storage_node_signs_the_node_and_nonce_it_sends(file_tx_submit):
    name = "UnregisterStorageNode"
    _, t = _transaction(name)
    signed = []

    def sign(message, key):
        signed.append(message)
        return sign_challenge(message, key, "Ed25519")

    client = WillowClient("http://api.test")
    await client.files.unregister_storage_node(t["node_did"], {
        "private_key": SEED, "public_key_id": PUBLIC_KEY_ID, "sign_function": sign, "nonce": t["nonce"],
    })
    (submit,) = file_tx_submit
    body = json.loads(submit.content)[name]
    assert signed == [unregister_storage_node_message(body["node_did"], body["nonce"])]
    _expect_signed(name, body)

    with pytest.raises(ValueError, match="line break"):
        await client.files.unregister_storage_node("did:willow:a\n", {
            "private_key": SEED, "public_key_id": PUBLIC_KEY_ID, "sign_function": sign, "nonce": 1,
        })
    assert len(file_tx_submit) == 1


# ---------------------------------------------------------------------------
# Registrations the node refuses for a data or file subgrove: refused before
# anything is signed.
# ---------------------------------------------------------------------------

_INDEXED_SCHEMA = json.dumps({
    "version": 1, "fields": {"a": "string"},
    "indexes": [{"name": "by_a", "fields": ["a"], "unique": False}], "required_fields": [],
})
BAD_SUBGROVE_IDS = ["", "-a", "_a", "a" * 65, "a b", "a:b", "a.b", "a/b", "café", "a\rb"]


@pytest.mark.parametrize("name", ["RegisterSubgrove (data)", "RegisterSubgrove (file)"])
@pytest.mark.parametrize("subgrove_id", BAD_SUBGROVE_IDS)
def test_a_storage_registration_with_an_id_the_node_refuses_is_not_signed(name, subgrove_id):
    _, tx = _transaction(name)
    with pytest.raises(ValueError, match="subgrove_id"):
        register_subgrove_message(dict(tx, subgrove_id=subgrove_id))


@pytest.mark.parametrize("subgrove_id", ["a", "0", "A-1_b", "x" * 64])
def test_a_storage_registration_takes_any_id_the_node_takes(subgrove_id):
    _, tx = _transaction("RegisterSubgrove (data)")
    assert register_subgrove_message(dict(tx, subgrove_id=subgrove_id)).startswith(
        f"RegisterSubgrove\nSubgrove: {subgrove_id}\n"
    )


@pytest.mark.parametrize("name", ["RegisterSubgrove (data)", "RegisterSubgrove (file)"])
def test_a_storage_registration_whose_schema_declares_indexes_is_not_signed(name):
    _, tx = _transaction(name)
    with pytest.raises(ValueError, match="Schema indexes are not supported"):
        register_subgrove_message(dict(tx, schema=_INDEXED_SCHEMA))


def test_the_storage_rules_leave_an_indexing_registration_alone():
    name = "RegisterSubgrove (indexing)"
    _, tx = _transaction(name)
    assert register_subgrove_message(tx) == VECTORS[name]["message"]
    register_subgrove_message(dict(tx, subgrove_id="idx:2", schema=_INDEXED_SCHEMA))


@pytest.mark.asyncio
async def test_register_subgrove_refuses_indexes_and_bad_ids_before_anything_is_sent():
    client, seen = _willow_client(0)
    schema = {"version": 1, "fields": {"a": {"type": "string"}}}
    request = {"subgrove_id": "sg-1", "name": "n", "owner_did": "did:willow:a", "schema": schema}
    for bad, match in (
        (dict(request, schema=dict(schema, indexes=[{"name": "i", "fields": ["a"]}])), "indexes are not supported"),
        (dict(request, schema={"version": 1, "fields": {"a": {"type": "string", "indexed": True}}}), "indexes are not supported"),
        (dict(request, subgrove_id="my data"), "subgrove_id"),
    ):
        with pytest.raises(ValueError, match=match):
            await client.registration.register_subgrove(bad)
    assert seen == []
    await client.registration.register_subgrove(request)
    assert json.loads(_sent(seen, "RegisterSubgrove")["schema"])["indexes"] == []
    await client.close()


@pytest.mark.asyncio
async def test_consensus_register_subgrove_refuses_indexes_and_bad_ids_before_reading_the_nonce():
    client = _consensus_client(0)
    with pytest.raises(ValueError, match="subgrove_id"):
        await client.register_subgrove("sg 1", "{}", "did:willow:a", SEED, PUBLIC_KEY_ID)
    with pytest.raises(ValueError, match="indexes"):
        await client.register_subgrove("sg-1", _INDEXED_SCHEMA, "did:willow:a", SEED, PUBLIC_KEY_ID)
    assert client._session.submitted == []
    assert client._session.read_nonces == 0


# ---------------------------------------------------------------------------
# File and storage-node transactions take the nonce the caller chose; the node
# refuses nonce 0, so there is no default.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("nonce", [None, 0, -1, True, "1"])
async def test_file_transactions_need_a_nonce(file_tx_submit, nonce):
    signing = {
        "owner_did": "did:willow:a", "private_key": SEED, "public_key_id": PUBLIC_KEY_ID,
        "sign_function": lambda message, key: sign_challenge(message, key, "Ed25519"),
    }
    if nonce is not None:
        signing["nonce"] = nonce
    client = WillowClient("http://api.test")
    with pytest.raises(ValueError, match="nonce"):
        await client.files.unregister_storage_node("did:willow:node", signing)
    with pytest.raises(ValueError, match="nonce"):
        await client.files.delete("sg", "f", signing)
    with pytest.raises(ValueError, match="nonce"):
        await client.files.upload("sg", "f", "a.txt", b"x", "http://storage.test", signing)
    assert file_tx_submit == []


@pytest.mark.asyncio
async def test_consensus_store_data_refuses_nan_before_anything_is_sent():
    client = _consensus_client(0)
    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(ValueError):
            await client.store_data("sg-1", "doc1", {"x": value}, "did:willow:a", SEED, PUBLIC_KEY_ID)
    assert client._session.submitted == []
    assert client._session.read_nonces == 0
