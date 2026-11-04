"""The messages data and file write transactions are signed over.

Each message is a set of lines joined by ``\\n`` (the byte 0x0A), with no
trailing newline, as UTF-8: the kind first, then one ``Label: value`` line
per field, the nonce last. It binds the transaction's nonce and every field
the transaction writes. Text fields go in verbatim, with no escaping or
normalization. Variable-length bytes appear as the lowercase hex SHA-256 of
the exact bytes the transaction carries; 32-byte fields appear as their
lowercase hex. Numbers are unsigned decimal.

A text field holding a line break (the byte 0x0A) is refused
(``ValueError``): the node refuses such a transaction, and the lines must read
back one way only.

The nonce in the message is the nonce in the transaction. A write that lands
in a block and is refused there after its signature and nonce verify still
spends its nonce; to retry, sign again under the next free nonce.

Ed25519 signs the message's UTF-8 bytes; secp256k1 signs their Keccak-256
(see ``willow.auth.sign_challenge``).

Registrations, key grants, and storage-node removals sign the same way:
GrantSubgroveKey, RotateSubgroveKey, and UnregisterStorageNode write every
field out; RegisterSubgrove binds its whole transaction through ``Config``,
the SHA-256 of the transaction's bincode with an empty signature
(``register_subgrove_unsigned_bincode``). RevokeSubgroveKey signs a
colon-joined form that binds every field it carries; RegisterDid signs the
node's compact JSON of the DID document.
"""

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

ByteField = Union[bytes, bytearray, str, Sequence[int]]

__all__ = [
    "store_data_message",
    "store_file_manifest_message",
    "delete_file_manifest_message",
    "register_subgrove_message",
    "register_subgrove_unsigned_bincode",
    "normalize_register_subgrove",
    "grant_subgrove_key_message",
    "rotate_subgrove_key_message",
    "revoke_subgrove_key_message",
    "unregister_storage_node_message",
    "register_did_message",
    "did_document_body",
]


def _field(label: str, value: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    # U+000A is the only code point whose UTF-8 holds the byte 0x0A.
    if "\n" in value:
        raise ValueError(f"{label} holds a line break, which a signed field can't")
    return f"{label}: {value}"


_U32_MAX = 2**32 - 1
_U64_MAX = 2**64 - 1


def _unsigned(label: str, value: int, maximum: int = _U64_MAX) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValueError(f"{label} must be an integer from 0 to {maximum}")
    return value


def _hex(label: str, value: ByteField, length: int) -> str:
    """``value`` (hex with or without ``0x``, bytes, or a list of ints) as lowercase hex."""
    if isinstance(value, str):
        raw = bytes.fromhex(value[2:] if value.startswith(("0x", "0X")) else value)
    elif isinstance(value, int):
        raise TypeError(f"{label} must be bytes, hex, or a list of ints")
    else:
        raw = bytes(value)
    if len(raw) != length:
        raise ValueError(f"{label} must be {length} bytes, got {len(raw)}")
    return raw.hex()


def store_data_message(
    subgrove_id: str,
    key: str,
    owner_did: str,
    data: Union[bytes, bytearray, str],
    nonce: int,
) -> str:
    """The message a StoreData transaction is signed over.

    ``data`` is the exact bytes the transaction's ``data`` field carries (a
    ``str`` is taken as its UTF-8 bytes); the message binds their SHA-256::

        StoreData
        Subgrove: <subgrove_id>
        Key: <key>
        Owner: <owner_did>
        DataHash: <hex SHA-256 of data>
        Nonce: <nonce>
    """
    if isinstance(data, str):
        data_bytes = data.encode("utf-8")
    elif isinstance(data, (bytes, bytearray, memoryview)):
        data_bytes = bytes(data)
    else:
        raise TypeError("data must be bytes or str")
    return "\n".join([
        "StoreData",
        _field("Subgrove", subgrove_id),
        _field("Key", key),
        _field("Owner", owner_did),
        f"DataHash: {hashlib.sha256(data_bytes).hexdigest()}",
        f"Nonce: {_unsigned('Nonce', nonce)}",
    ])


def store_file_manifest_message(
    subgrove_id: str,
    file_key: str,
    owner_did: str,
    filename: str,
    content_type: str,
    total_size: int,
    content_hash: ByteField,
    chunk_count: int,
    chunk_size: int,
    chunk_merkle_root: ByteField,
    nonce: int,
    encryption: Optional[Tuple[int, ByteField]] = None,
) -> str:
    """The message a StoreFileManifest transaction is signed over.

    ``content_hash`` and ``chunk_merkle_root`` are 32 bytes (bytes, hex, or a
    list of ints). ``encryption`` is ``None`` when the transaction carries no
    ``encryption``, else ``(key_epoch, nonce)`` with the 24-byte XChaCha20
    nonce::

        StoreFileManifest
        Subgrove: <subgrove_id>
        Key: <file_key>
        Owner: <owner_did>
        Filename: <filename>
        ContentType: <content_type>
        TotalSize: <total_size>
        ContentHash: <hex content_hash>
        ChunkCount: <chunk_count>
        ChunkSize: <chunk_size>
        ChunkMerkleRoot: <hex chunk_merkle_root>
        Encryption: none | <key_epoch>:<hex nonce>
        Nonce: <nonce>
    """
    if encryption is None:
        encryption_line = "Encryption: none"
    else:
        key_epoch, encryption_nonce = encryption
        encryption_line = (
            f"Encryption: {_unsigned('Encryption key epoch', key_epoch)}:"
            f"{_hex('Encryption nonce', encryption_nonce, 24)}"
        )
    return "\n".join([
        "StoreFileManifest",
        _field("Subgrove", subgrove_id),
        _field("Key", file_key),
        _field("Owner", owner_did),
        _field("Filename", filename),
        _field("ContentType", content_type),
        f"TotalSize: {_unsigned('TotalSize', total_size)}",
        f"ContentHash: {_hex('ContentHash', content_hash, 32)}",
        f"ChunkCount: {_unsigned('ChunkCount', chunk_count, _U32_MAX)}",
        f"ChunkSize: {_unsigned('ChunkSize', chunk_size, _U32_MAX)}",
        f"ChunkMerkleRoot: {_hex('ChunkMerkleRoot', chunk_merkle_root, 32)}",
        encryption_line,
        f"Nonce: {_unsigned('Nonce', nonce)}",
    ])


def delete_file_manifest_message(
    subgrove_id: str,
    file_key: str,
    owner_did: str,
    nonce: int,
) -> str:
    """The message a DeleteFileManifest transaction is signed over::

        DeleteFileManifest
        Subgrove: <subgrove_id>
        Key: <file_key>
        Owner: <owner_did>
        Nonce: <nonce>
    """
    return "\n".join([
        "DeleteFileManifest",
        _field("Subgrove", subgrove_id),
        _field("Key", file_key),
        _field("Owner", owner_did),
        f"Nonce: {_unsigned('Nonce', nonce)}",
    ])


# ---------------------------------------------------------------------------
# The second set: registrations, key grants, and storage-node removals.
# ---------------------------------------------------------------------------

_U8_MAX = 2**8 - 1
_U128_MAX = 2**128 - 1


def _fields_of(value: Any, label: str) -> Mapping:
    """``value``'s fields as a mapping: a mapping itself, or an SDK object
    (``to_dict()``, a dataclass, or a pydantic model)."""
    if isinstance(value, Mapping):
        return value
    if callable(getattr(value, "to_dict", None)):
        return value.to_dict()
    if hasattr(value, "__dataclass_fields__"):
        return {name: getattr(value, name) for name in value.__dataclass_fields__}
    if callable(getattr(value, "model_dump", None)):
        return value.model_dump()
    raise TypeError(f"{label} must be a mapping")


def _required(fields: Mapping, key: str, label: str) -> Any:
    if key not in fields:
        raise ValueError(f"{label}.{key} is required")
    return fields[key]


def _given(fields: Mapping, key: str, default: Any) -> Any:
    """``fields[key]``, or ``default`` when it is absent or ``None``."""
    value = fields.get(key)
    return default if value is None else value


def _text(label: str, value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string")
    return value


def _texts(label: str, value: Any) -> List[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise TypeError(f"{label} must be a list of strings")
    return [_text(f"{label}[{i}]", v) for i, v in enumerate(value)]


def _boolean(label: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{label} must be true or false")
    return value


def _u128(label: str, value: Any, decimal_text: bool = False) -> int:
    """A u128; ``decimal_text`` also takes the decimal string the node accepts
    for this field."""
    if decimal_text and isinstance(value, str) and value.isascii() and value.isdigit():
        value = int(value)
    return _unsigned(label, value, _U128_MAX)


def _byte_values(label: str, value: Any, length: Optional[int] = None) -> List[int]:
    """Bytes, hex (with or without ``0x``), or a list of ints, as the list of
    ints a byte field is in the transaction's JSON."""
    if isinstance(value, str):
        try:
            raw = bytes.fromhex(value[2:] if value.startswith(("0x", "0X")) else value)
        except ValueError:
            raise ValueError(f"{label} must be bytes, hex, or a list of ints") from None
    elif isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    elif isinstance(value, (list, tuple)):
        if not all(isinstance(b, int) and not isinstance(b, bool) and 0 <= b <= 255 for b in value):
            raise ValueError(f"{label} must be bytes, hex, or a list of ints from 0 to 255")
        raw = bytes(value)
    else:
        raise TypeError(f"{label} must be bytes, hex, or a list of ints")
    if length is not None and len(raw) != length:
        raise ValueError(f"{label} must be {length} bytes, got {len(raw)}")
    return list(raw)


def _optional(value: Any, normalize: Callable[[Any], Any]) -> Any:
    return None if value is None else normalize(value)


def _variant(label: str, value: Any, variants: Sequence[str]) -> Tuple[str, Any]:
    """An externally tagged enum value: ``"Variant"`` or ``{"Variant": payload}``."""
    if isinstance(value, str):
        name, payload = value, None
    elif isinstance(value, Mapping) and len(value) == 1:
        ((name, payload),) = value.items()
    else:
        raise ValueError(f"{label} must be one of {', '.join(variants)}")
    if name not in variants:
        raise ValueError(f"{label} must be one of {', '.join(variants)}, got {name!r}")
    return name, payload


def _unit_variant(label: str, value: Any, variants: Sequence[str]) -> str:
    name, payload = _variant(label, value, variants)
    if payload is not None:
        raise ValueError(f"{label} {name} takes no value")
    return name


_TEE_TYPES = ("AwsNitro", "IntelSgx", "AmdSev")
_SUBGROVE_MODES = ("DataStorage", "FileStorage", "BlockchainIndexing")
_EXECUTION_MODES = ("ConsensusExecution", "IndexerExecution", "TeeExecution")
_RETENTION_WINDOWS = ("Blocks", "Seconds", "Indefinite", "VerifyOnly")
_HISTORICAL_AUTH_MODES = ("BftEquivalent", "CanonizedAccumulator")
_COMMITMENT_FREQUENCIES = ("EveryUpdate", "EveryNBlocks", "EveryNSeconds", "Never")

# The node's default epoch length, in blocks, for an IndexerConfig without one.
_DEFAULT_EPOCH_LENGTH = 100


def _key_grant(label: str, grant: Any) -> Dict[str, Any]:
    g = _fields_of(grant, label)
    return {
        "grantee_did": _text(f"{label}.grantee_did", _required(g, "grantee_did", label)),
        "key_epoch": _unsigned(f"{label}.key_epoch", _required(g, "key_epoch", label), _U32_MAX),
        "grantee_public_key_id": _text(
            f"{label}.grantee_public_key_id", _required(g, "grantee_public_key_id", label)
        ),
        "ephemeral_public_key": _byte_values(
            f"{label}.ephemeral_public_key", _required(g, "ephemeral_public_key", label)
        ),
        "encrypted_key": _byte_values(f"{label}.encrypted_key", _required(g, "encrypted_key", label)),
        "granted_by": _text(f"{label}.granted_by", _required(g, "granted_by", label)),
        "granted_at": _unsigned(f"{label}.granted_at", _required(g, "granted_at", label)),
    }


def _read_pricing(label: str, pricing: Any) -> Dict[str, Any]:
    p = _fields_of(pricing, label)
    return {
        "enabled": _boolean(f"{label}.enabled", _required(p, "enabled", label)),
        "price_per_query": _u128(f"{label}.price_per_query", _required(p, "price_per_query", label)),
        "owner_revenue_share_bps": _unsigned(
            f"{label}.owner_revenue_share_bps",
            _required(p, "owner_revenue_share_bps", label),
            _U32_MAX,
        ),
    }


def _free_readers(label: str, fields: Mapping, alias: bool) -> List[str]:
    if alias and "readers" in fields:
        if "free_readers" in fields:
            raise ValueError(f"{label} has both free_readers and readers")
        return _texts(f"{label}.free_readers", fields["readers"])
    return _texts(f"{label}.free_readers", _required(fields, "free_readers", label))


def _retention_window(label: str, value: Any) -> Any:
    # The SDK's RetentionWindow objects ({type, value}) take the node's form.
    if not isinstance(value, (str, Mapping)) and hasattr(value, "type"):
        kind = value.type
        value = kind if kind in ("Indefinite", "VerifyOnly") else {kind: getattr(value, "value", None)}
    name, payload = _variant(label, value, _RETENTION_WINDOWS)
    if name in ("Blocks", "Seconds"):
        return {name: _unsigned(f"{label}.{name}", payload)}
    if payload is not None:
        raise ValueError(f"{label} {name} takes no value")
    return name


def _execution_mode(label: str, value: Any) -> Any:
    name, payload = _variant(label, value, _EXECUTION_MODES)
    if name == "ConsensusExecution":
        if payload is not None:
            raise ValueError(f"{label} ConsensusExecution takes no value")
        return name
    p = _fields_of(payload, f"{label}.{name}")
    if name == "IndexerExecution":
        rate = _required(p, "sampling_rate_percent", f"{label}.{name}")
        return {name: {"sampling_rate_percent": _unsigned(f"{label}.{name}.sampling_rate_percent", rate, _U8_MAX)}}
    tee = _required(p, "tee_type", f"{label}.{name}")
    return {name: {"tee_type": _unit_variant(f"{label}.{name}.tee_type", tee, _TEE_TYPES)}}


def _indexer_config(label: str, config: Any) -> Dict[str, Any]:
    c = _fields_of(config, label)
    return {
        "min_indexers": _unsigned(f"{label}.min_indexers", _required(c, "min_indexers", label), _U8_MAX),
        "max_indexers": _unsigned(f"{label}.max_indexers", _required(c, "max_indexers", label), _U8_MAX),
        "reward_per_epoch": _u128(
            f"{label}.reward_per_epoch", _required(c, "reward_per_epoch", label), decimal_text=True
        ),
        "epoch_length": _unsigned(f"{label}.epoch_length", c.get("epoch_length", _DEFAULT_EPOCH_LENGTH)),
        "min_indexer_stake": _u128(
            f"{label}.min_indexer_stake", _required(c, "min_indexer_stake", label), decimal_text=True
        ),
    }


def _config_hash(label: str, value: Any) -> List[int]:
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)) or len(value) != 4:
        raise ValueError(f"{label} must be four u32 values")
    return [_unsigned(f"{label}[{i}]", v, _U32_MAX) for i, v in enumerate(value)]


def _completeness(label: str, value: Any) -> Dict[str, Any]:
    c = _fields_of(value, label)
    return {
        "log_config_hash": _config_hash(f"{label}.log_config_hash", _required(c, "log_config_hash", label)),
        "tx_config_hash": _config_hash(f"{label}.tx_config_hash", _required(c, "tx_config_hash", label)),
        "deferred": _boolean(f"{label}.deferred", c.get("deferred", False)),
        "bond_amount": _u128(f"{label}.bond_amount", c.get("bond_amount", 0)),
    }


def _wasm_module(label: str, module: Any) -> Dict[str, Any]:
    m = _fields_of(module, label)
    return {
        "name": _text(f"{label}.name", _required(m, "name", label)),
        "hash": _byte_values(f"{label}.hash", _required(m, "hash", label), 32),
        "content": _byte_values(f"{label}.content", _required(m, "content", label)),
    }


def _subgrove_mode(mode: Any) -> Dict[str, Any]:
    if mode is None:
        # The node's mode for a body without one.
        return {"DataStorage": {"name": "", "writers": [], "free_readers": [], "read_pricing": None}}
    name, payload = _variant("mode", mode, _SUBGROVE_MODES)
    label = f"mode.{name}"
    p = _fields_of(payload, label)
    if name == "DataStorage":
        return {name: {
            "name": _text(f"{label}.name", _required(p, "name", label)),
            "writers": _texts(f"{label}.writers", _required(p, "writers", label)),
            "free_readers": _free_readers(label, p, alias=True),
            "read_pricing": _optional(p.get("read_pricing"), lambda v: _read_pricing(f"{label}.read_pricing", v)),
        }}
    if name == "FileStorage":
        return {name: {
            "name": _text(f"{label}.name", _required(p, "name", label)),
            "max_file_size": _unsigned(f"{label}.max_file_size", _required(p, "max_file_size", label)),
            "replication_factor": _unsigned(
                f"{label}.replication_factor", _required(p, "replication_factor", label), _U8_MAX
            ),
            "writers": _texts(f"{label}.writers", _required(p, "writers", label)),
            "free_readers": _free_readers(label, p, alias=False),
            "read_pricing": _optional(p.get("read_pricing"), lambda v: _read_pricing(f"{label}.read_pricing", v)),
            "retention_period": _unsigned(f"{label}.retention_period", _given(p, "retention_period", 0)),
        }}
    modules = _given(p, "wasm_modules", [])
    if isinstance(modules, (str, bytes)) or not isinstance(modules, (list, tuple)):
        raise TypeError(f"{label}.wasm_modules must be a list")
    return {name: {
        "manifest_content": _byte_values(f"{label}.manifest_content", _required(p, "manifest_content", label)),
        "wasm_modules": [_wasm_module(f"{label}.wasm_modules[{i}]", m) for i, m in enumerate(modules)],
        "execution_mode": _execution_mode(f"{label}.execution_mode", _required(p, "execution_mode", label)),
        "indexer_config": _indexer_config(f"{label}.indexer_config", _required(p, "indexer_config", label)),
        "retention_window": _retention_window(
            f"{label}.retention_window", _given(p, "retention_window", "Indefinite")
        ),
        "completeness": _optional(p.get("completeness"), lambda v: _completeness(f"{label}.completeness", v)),
        "historical_auth_mode": _unit_variant(
            f"{label}.historical_auth_mode", _given(p, "historical_auth_mode", "BftEquivalent"),
            _HISTORICAL_AUTH_MODES,
        ),
    }}


def _commitment_frequency(label: str, value: Any) -> Any:
    if callable(getattr(value, "to_json", None)):  # willow.privacy.CommitmentFrequency
        value = value.to_json()
    name, payload = _variant(label, value, _COMMITMENT_FREQUENCIES)
    if name in ("EveryNBlocks", "EveryNSeconds"):
        return {name: _unsigned(f"{label}.{name}", payload)}
    if payload is not None:
        raise ValueError(f"{label} {name} takes no value")
    return name


def _privacy(value: Any) -> Dict[str, Any]:
    p = _fields_of(value, "privacy")
    return {
        "allowed_indexers": _optional(p.get("allowed_indexers"), lambda v: _texts("privacy.allowed_indexers", v)),
        "commitment_frequency": _commitment_frequency(
            "privacy.commitment_frequency", _required(p, "commitment_frequency", "privacy")
        ),
    }


def _template_config(value: Any) -> Dict[str, Any]:
    label = "template_config"
    c = _fields_of(value, label)
    return {
        "template_id": _text(f"{label}.template_id", _required(c, "template_id", label)),
        "template_version": _unsigned(
            f"{label}.template_version", _required(c, "template_version", label), _U32_MAX
        ),
        "variant_id": _text(f"{label}.variant_id", _required(c, "variant_id", label)),
        "parameters": _byte_values(f"{label}.parameters", _required(c, "parameters", label)),
        "contracts": _texts(f"{label}.contracts", _required(c, "contracts", label)),
        "event_signatures": _texts(f"{label}.event_signatures", _required(c, "event_signatures", label)),
        "chain": _optional(c.get("chain"), lambda v: _text(f"{label}.chain", v)),
    }


def normalize_register_subgrove(tx: Any) -> Dict[str, Any]:
    """A RegisterSubgrove transaction as the node decodes it, every field explicit.

    ``tx`` is the transaction's JSON object (the value under
    ``"RegisterSubgrove"``) or a mapping of the same fields. Fields the node
    fills in when a body leaves them out take the node's values:
    ``description`` ``""``, ``admins`` ``[]``, ``initial_funding``,
    ``privacy``, ``initial_owner_key_grant``, and ``template_config``
    ``None``, ``checkpoint_verification`` ``{"required_tee": None}``,
    ``confirmation_depth`` ``0``, ``cryptographic_completeness`` ``False``,
    and no ``mode`` is DataStorage with an empty name, writers, and free
    readers; within a mode, ``read_pricing`` and ``completeness`` ``None``,
    ``retention_period`` ``0``, ``wasm_modules`` ``[]``, ``retention_window``
    ``"Indefinite"``, ``epoch_length`` ``100``, and ``historical_auth_mode``
    ``"BftEquivalent"``. Every other field is required. Byte fields (bytes,
    hex, or lists of ints) become lists of ints, as ``/tx/submit`` reads them;
    enums take their JSON form (``"Indefinite"``, ``{"Blocks": 1000}``).

    Send exactly what this returns, so the node hashes what was signed.

    Raises:
        ValueError, TypeError: A field is missing, of the wrong type, or out of
            its range.
    """
    t = _fields_of(tx, "RegisterSubgrove")
    label = "RegisterSubgrove"
    checkpoint = _given(t, "checkpoint_verification", {})
    checkpoint = _fields_of(checkpoint, f"{label}.checkpoint_verification")
    return {
        "subgrove_id": _text("subgrove_id", _required(t, "subgrove_id", label)),
        "name": _text("name", _required(t, "name", label)),
        "description": _text("description", _given(t, "description", "")),
        "schema": _text("schema", _required(t, "schema", label)),
        "owner_did": _text("owner_did", _required(t, "owner_did", label)),
        "admins": _texts("admins", _given(t, "admins", [])),
        "initial_funding": _optional(
            t.get("initial_funding"), lambda v: _u128("initial_funding", v, decimal_text=True)
        ),
        "checkpoint_verification": {
            "required_tee": _optional(
                checkpoint.get("required_tee"),
                lambda v: _unit_variant("checkpoint_verification.required_tee", v, _TEE_TYPES),
            ),
        },
        "mode": _subgrove_mode(t.get("mode")),
        "privacy": _optional(t.get("privacy"), _privacy),
        "initial_owner_key_grant": _optional(
            t.get("initial_owner_key_grant"), lambda g: _key_grant("initial_owner_key_grant", g)
        ),
        "template_config": _optional(t.get("template_config"), _template_config),
        "confirmation_depth": _unsigned("confirmation_depth", _given(t, "confirmation_depth", 0), _U32_MAX),
        "signature": _byte_values("signature", _given(t, "signature", [])),
        "public_key_id": _text("public_key_id", _required(t, "public_key_id", label)),
        "nonce": _unsigned("Nonce", _required(t, "nonce", label)),
        "cryptographic_completeness": _boolean(
            "cryptographic_completeness", _given(t, "cryptographic_completeness", False)
        ),
    }


class _Bincode:
    """bincode 1.x default: fixed-width little-endian integers, u64 lengths,
    u32 enum variant indexes, a 1-byte Option tag, fixed-size arrays with no
    length."""

    def __init__(self) -> None:
        self.out = bytearray()

    def u8(self, v: int) -> None:
        self.out += v.to_bytes(1, "little")

    def u32(self, v: int) -> None:
        self.out += v.to_bytes(4, "little")

    def u64(self, v: int) -> None:
        self.out += v.to_bytes(8, "little")

    def u128(self, v: int) -> None:
        self.out += v.to_bytes(16, "little")

    def boolean(self, v: bool) -> None:
        self.u8(1 if v else 0)

    def byte_vec(self, b: Sequence[int]) -> None:
        self.u64(len(b))
        self.out += bytes(b)

    def string(self, s: str) -> None:
        self.byte_vec(s.encode("utf-8"))

    def array(self, b: Sequence[int]) -> None:
        self.out += bytes(b)

    def strings(self, xs: Sequence[str]) -> None:
        self.u64(len(xs))
        for x in xs:
            self.string(x)

    def option(self, v: Any, write: Callable[[Any], None]) -> None:
        if v is None:
            self.u8(0)
        else:
            self.u8(1)
            write(v)

    def variant(self, value: Any, variants: Sequence[str]) -> Any:
        """Write the variant index of a normalized enum value; return its payload."""
        name, payload = (value, None) if isinstance(value, str) else next(iter(value.items()))
        self.u32(variants.index(name))
        return payload


def _encode_read_pricing(w: _Bincode, p: Dict[str, Any]) -> None:
    w.boolean(p["enabled"])
    w.u128(p["price_per_query"])
    w.u32(p["owner_revenue_share_bps"])


def _encode_key_grant(w: _Bincode, g: Dict[str, Any]) -> None:
    w.string(g["grantee_did"])
    w.u32(g["key_epoch"])
    w.string(g["grantee_public_key_id"])
    w.byte_vec(g["ephemeral_public_key"])
    w.byte_vec(g["encrypted_key"])
    w.string(g["granted_by"])
    w.u64(g["granted_at"])


def _encode_mode(w: _Bincode, mode: Dict[str, Any]) -> None:
    m = w.variant(mode, _SUBGROVE_MODES)
    if "DataStorage" in mode:
        w.string(m["name"])
        w.strings(m["writers"])
        w.strings(m["free_readers"])
        w.option(m["read_pricing"], lambda p: _encode_read_pricing(w, p))
    elif "FileStorage" in mode:
        w.string(m["name"])
        w.u64(m["max_file_size"])
        w.u8(m["replication_factor"])
        w.strings(m["writers"])
        w.strings(m["free_readers"])
        w.option(m["read_pricing"], lambda p: _encode_read_pricing(w, p))
        w.u64(m["retention_period"])
    else:
        w.byte_vec(m["manifest_content"])
        w.u64(len(m["wasm_modules"]))
        for module in m["wasm_modules"]:
            w.string(module["name"])
            w.array(module["hash"])
            w.byte_vec(module["content"])
        execution = w.variant(m["execution_mode"], _EXECUTION_MODES)
        if "IndexerExecution" in m["execution_mode"]:
            w.u8(execution["sampling_rate_percent"])
        elif "TeeExecution" in m["execution_mode"]:
            w.u32(_TEE_TYPES.index(execution["tee_type"]))
        c = m["indexer_config"]
        w.u8(c["min_indexers"])
        w.u8(c["max_indexers"])
        w.u128(c["reward_per_epoch"])
        w.u64(c["epoch_length"])
        w.u128(c["min_indexer_stake"])
        retention = w.variant(m["retention_window"], _RETENTION_WINDOWS)
        if retention is not None:
            w.u64(retention)

        def completeness(x: Dict[str, Any]) -> None:
            for v in x["log_config_hash"] + x["tx_config_hash"]:
                w.u32(v)
            w.boolean(x["deferred"])
            w.u128(x["bond_amount"])

        w.option(m["completeness"], completeness)
        w.u32(_HISTORICAL_AUTH_MODES.index(m["historical_auth_mode"]))


def register_subgrove_unsigned_bincode(tx: Any) -> bytes:
    """The bincode a RegisterSubgrove message's ``Config`` hashes.

    ``bincode::serialize`` (bincode 1.x default) of the ``RegisterSubgroveTx``
    struct, not the ``Transaction`` enum, with ``signature`` empty and every
    other field as the node decodes ``tx`` (see
    ``normalize_register_subgrove``). Every mode encodes.
    """
    t = normalize_register_subgrove(tx)
    w = _Bincode()
    for key in ("subgrove_id", "name", "description", "schema", "owner_did"):
        w.string(t[key])
    w.strings(t["admins"])
    w.option(t["initial_funding"], w.u128)
    w.option(
        t["checkpoint_verification"]["required_tee"], lambda v: w.u32(_TEE_TYPES.index(v))
    )
    _encode_mode(w, t["mode"])

    def privacy(p: Dict[str, Any]) -> None:
        w.option(p["allowed_indexers"], w.strings)
        n = w.variant(p["commitment_frequency"], _COMMITMENT_FREQUENCIES)
        if n is not None:
            w.u64(n)

    w.option(t["privacy"], privacy)
    w.option(t["initial_owner_key_grant"], lambda g: _encode_key_grant(w, g))

    def template(c: Dict[str, Any]) -> None:
        w.string(c["template_id"])
        w.u32(c["template_version"])
        w.string(c["variant_id"])
        w.byte_vec(c["parameters"])
        w.strings(c["contracts"])
        w.strings(c["event_signatures"])
        w.option(c["chain"], w.string)

    w.option(t["template_config"], template)
    w.u32(t["confirmation_depth"])
    w.byte_vec(b"")  # the signature, empty
    w.string(t["public_key_id"])
    w.u64(t["nonce"])
    w.boolean(t["cryptographic_completeness"])
    return bytes(w.out)


# A subgrove ID the node takes for a data or file subgrove.
_STORAGE_SUBGROVE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


# The field types of the node's ``SchemaDefinition`` (``FieldType``, lowercase).
SCHEMA_FIELD_TYPES = ("string", "number", "boolean", "array", "object", "bytes")


class _JsonObject(dict):
    duplicates: Tuple[str, ...] = ()


def _json_object(pairs: List[Tuple[str, Any]]) -> "_JsonObject":
    obj = _JsonObject(pairs)
    if len(obj) != len(pairs):
        seen: set = set()
        obj.duplicates = tuple(k for k, _ in pairs if k in seen or seen.add(k))
    return obj


def _schema_definition_rules(text: str) -> None:
    """Refuse a schema the node can't parse as its ``SchemaDefinition``:
    a JSON object of ``version`` (u32, default 1), ``fields`` (an object
    mapping each name to one of ``SCHEMA_FIELD_TYPES``, default empty),
    ``indexes`` (default empty), and ``required_fields`` (a list of names,
    default empty). Other keys are ignored, as the node ignores them. The
    node refuses one in its block (spending the nonce); this SDK also
    refuses any ``indexes``."""
    try:
        schema = json.loads(text, object_pairs_hook=_json_object)
    except ValueError as e:
        raise ValueError(f"schema is not JSON the node can parse: {e}") from None
    if not isinstance(schema, dict):
        raise ValueError("schema must be a JSON object: the node's SchemaDefinition")
    duplicates = [k for k in schema.duplicates if k in ("version", "fields", "indexes", "required_fields")]
    if duplicates:
        raise ValueError(f"schema repeats {duplicates[0]!r}: the node refuses a duplicate field")
    if "version" in schema:
        version = schema["version"]
        if type(version) is not int or not 0 <= version <= _U32_MAX:
            raise ValueError(f"schema version must be an integer from 0 to {_U32_MAX}, not {version!r}")
    fields = schema.get("fields", {})
    if not isinstance(fields, dict):
        raise ValueError("schema fields must be an object mapping each field name to its type")
    for name, field_type in fields.items():
        if not isinstance(field_type, str) or field_type not in SCHEMA_FIELD_TYPES:
            raise ValueError(
                f"schema field {name!r} has type {field_type!r}; the node takes "
                + ", ".join(SCHEMA_FIELD_TYPES)
            )
    indexes = schema.get("indexes", [])
    if not isinstance(indexes, list):
        raise ValueError("schema indexes must be a list")
    if indexes:
        raise ValueError("Schema indexes are not supported: this SDK refuses a schema that declares indexes")
    required = schema.get("required_fields", [])
    if not isinstance(required, list) or not all(isinstance(r, str) for r in required):
        raise ValueError("schema required_fields must be a list of field names")


def _storage_registration_rules(t: Dict[str, Any]) -> None:
    """Refuse a DataStorage or FileStorage registration the node refuses: a
    subgrove ID that isn't 1 to 64 ASCII letters, digits, ``-``, or ``_``
    starting with a letter or digit, or a schema that doesn't parse as the
    node's ``SchemaDefinition`` (see ``_schema_definition_rules``) or that
    declares indexes."""
    if "BlockchainIndexing" in t["mode"]:
        return
    if not _STORAGE_SUBGROVE_ID.fullmatch(t["subgrove_id"]):
        raise ValueError(
            f"subgrove_id {t['subgrove_id']!r} is not one the node takes: 1 to 64 ASCII "
            "letters, digits, '-', or '_', starting with a letter or digit"
        )
    _schema_definition_rules(t["schema"])


def register_subgrove_message(tx: Any) -> str:
    """The message a RegisterSubgrove transaction is signed over::

        RegisterSubgrove
        Subgrove: <subgrove_id>
        Owner: <owner_did>
        Config: <hex SHA-256 of register_subgrove_unsigned_bincode(tx)>
        Nonce: <nonce>

    ``tx`` is the transaction's JSON object; ``Config`` binds every field of
    it but the signature, as the node decodes it. Send
    ``normalize_register_subgrove(tx)`` and sign this message over it.

    Raises:
        ValueError: A field is out of range or a line holds a line break, or
            a DataStorage or FileStorage registration has a subgrove ID the
            node refuses (not 1 to 64 ASCII letters, digits, ``-``, or ``_``
            starting with a letter or digit), or a schema that doesn't parse
            as the node's ``SchemaDefinition`` or declares indexes.
    """
    t = normalize_register_subgrove(tx)
    lines = [
        "RegisterSubgrove",
        _field("Subgrove", t["subgrove_id"]),
        _field("Owner", t["owner_did"]),
    ]
    _storage_registration_rules(t)
    config = hashlib.sha256(register_subgrove_unsigned_bincode(t)).hexdigest()
    return "\n".join(lines + [f"Config: {config}", f"Nonce: {t['nonce']}"])


def _grant_lines(grant: Dict[str, Any]) -> List[str]:
    return [
        _field("Grantee", grant["grantee_did"]),
        _field("GranteeKey", grant["grantee_public_key_id"]),
        f"KeyEpoch: {grant['key_epoch']}",
        f"EphemeralKey: {bytes(grant['ephemeral_public_key']).hex()}",
        f"EncryptedKey: {bytes(grant['encrypted_key']).hex()}",
        _field("GrantedBy", grant["granted_by"]),
        f"GrantedAt: {grant['granted_at']}",
    ]


def grant_subgrove_key_message(subgrove_id: str, sender_did: str, grant: Any, nonce: int) -> str:
    """The message a GrantSubgroveKey transaction is signed over.

    ``grant`` is its ``encrypted_key_grant`` (a mapping or an
    ``EncryptedKeyGrant``; byte fields as bytes, hex, or lists of ints)::

        GrantSubgroveKey
        Subgrove: <subgrove_id>
        Sender: <sender_did>
        Grantee: <grantee_did>
        GranteeKey: <grantee_public_key_id>
        KeyEpoch: <key_epoch>
        EphemeralKey: <hex ephemeral_public_key>
        EncryptedKey: <hex encrypted_key>
        GrantedBy: <granted_by>
        GrantedAt: <granted_at>
        Nonce: <nonce>
    """
    return "\n".join(
        ["GrantSubgroveKey", _field("Subgrove", subgrove_id), _field("Sender", sender_did)]
        + _grant_lines(_key_grant("grant", grant))
        + [f"Nonce: {_unsigned('Nonce', nonce)}"]
    )


def rotate_subgrove_key_message(
    subgrove_id: str, sender_did: str, new_epoch: int, new_grants: Sequence[Any], nonce: int
) -> str:
    """The message a RotateSubgroveKey transaction is signed over::

        RotateSubgroveKey
        Subgrove: <subgrove_id>
        Sender: <sender_did>
        NewEpoch: <new_epoch>
        Grants: <number of new_grants>
        <each grant's seven lines, Grantee to GrantedAt, in order>
        Nonce: <nonce>
    """
    if isinstance(new_grants, (str, bytes, Mapping)) or not isinstance(new_grants, (list, tuple)):
        raise TypeError("new_grants must be a list of grants")
    lines = [
        "RotateSubgroveKey",
        _field("Subgrove", subgrove_id),
        _field("Sender", sender_did),
        f"NewEpoch: {_unsigned('NewEpoch', new_epoch, _U32_MAX)}",
        f"Grants: {len(new_grants)}",
    ]
    for i, grant in enumerate(new_grants):
        lines += _grant_lines(_key_grant(f"new_grants[{i}]", grant))
    return "\n".join(lines + [f"Nonce: {_unsigned('Nonce', nonce)}"])


def revoke_subgrove_key_message(subgrove_id: str, revokee_did: str, sender_did: str, nonce: int) -> str:
    """The message a RevokeSubgroveKey transaction is signed over:
    ``RevokeSubgroveKey:<subgrove_id>:<revokee_did>:<sender_did>:<nonce>``.
    It binds every field the transaction carries."""
    return (
        f"RevokeSubgroveKey:{_text('subgrove_id', subgrove_id)}:{_text('revokee_did', revokee_did)}"
        f":{_text('sender_did', sender_did)}:{_unsigned('Nonce', nonce)}"
    )


def unregister_storage_node_message(node_did: str, nonce: int) -> str:
    """The message an UnregisterStorageNode transaction is signed over::

        UnregisterStorageNode
        Node: <node_did>
        Nonce: <nonce>
    """
    return "\n".join([
        "UnregisterStorageNode",
        _field("Node", node_did),
        f"Nonce: {_unsigned('Nonce', nonce)}",
    ])


def _optional_text(label: str, value: Any) -> Optional[str]:
    return None if value is None else _text(label, value)


def did_document_body(did_document: Any) -> Dict[str, Any]:
    """A DID document as the node decodes it, in its field order.

    Takes a ``DidDocument`` or a mapping in its JSON form (``public_keys``
    entries with ``type``; ``service`` entries with ``type`` and
    ``service_endpoint``). Fields the node does not read are dropped; send
    this, so the node serializes back exactly what was signed.
    """
    if callable(getattr(did_document, "model_dump", None)):
        did_document = did_document.model_dump(by_alias=True)
    d = _fields_of(did_document, "did_document")
    label = "did_document"

    def public_key(i: int, value: Any) -> Dict[str, Any]:
        k = _fields_of(value, f"{label}.public_keys[{i}]")
        kl = f"{label}.public_keys[{i}]"
        key_type = k["type"] if "type" in k else _required(k, "key_type", kl)
        return {
            "id": _text(f"{kl}.id", _required(k, "id", kl)),
            "type": _text(f"{kl}.type", key_type),
            "controller": _text(f"{kl}.controller", _required(k, "controller", kl)),
            "public_key_base58": _optional_text(f"{kl}.public_key_base58", k.get("public_key_base58")),
            "public_key_hex": _optional_text(f"{kl}.public_key_hex", k.get("public_key_hex")),
        }

    def service(i: int, value: Any) -> Dict[str, Any]:
        s = _fields_of(value, f"{label}.service[{i}]")
        sl = f"{label}.service[{i}]"
        return {
            "id": _text(f"{sl}.id", _required(s, "id", sl)),
            "type": _text(f"{sl}.type", s["type"] if "type" in s else _required(s, "service_type", sl)),
            "service_endpoint": _text(
                f"{sl}.service_endpoint",
                s["service_endpoint"] if "service_endpoint" in s else _required(s, "endpoint", sl),
            ),
        }

    def proof(value: Any) -> Dict[str, Any]:
        p = _fields_of(value, f"{label}.proof")
        pl = f"{label}.proof"
        return {
            "type": _text(f"{pl}.type", p["type"] if "type" in p else _required(p, "proof_type", pl)),
            "created": _unsigned(f"{pl}.created", _required(p, "created", pl)),
            "verification_method": _text(
                f"{pl}.verification_method", _required(p, "verification_method", pl)
            ),
            "proof_purpose": _text(f"{pl}.proof_purpose", _required(p, "proof_purpose", pl)),
            "jws": _text(f"{pl}.jws", _required(p, "jws", pl)),
        }

    keys = _required(d, "public_keys", label)
    services = _given(d, "service", [])
    for name, value in (("public_keys", keys), ("service", services)):
        if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, (list, tuple)):
            raise TypeError(f"{label}.{name} must be a list")
    return {
        "id": _text(f"{label}.id", _required(d, "id", label)),
        "public_keys": [public_key(i, k) for i, k in enumerate(keys)],
        "authentication": _texts(f"{label}.authentication", _required(d, "authentication", label)),
        "service": [service(i, s) for i, s in enumerate(services)],
        "created": _unsigned(f"{label}.created", _required(d, "created", label)),
        "updated": _unsigned(f"{label}.updated", _required(d, "updated", label)),
        "proof": _optional(d.get("proof"), proof),
    }


def register_did_message(did_document: Any) -> str:
    """The message a RegisterDid transaction is signed over: the node's
    compact JSON of the DID document (``did_document_body``), its fields in
    the node's order, text unescaped beyond JSON's required escapes."""
    return json.dumps(
        did_document_body(did_document), separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
