"""Tests for the canonical WillowManifest builder."""

import json

import pytest

from willow.manifest import (
    MANIFEST_SPEC_VERSION,
    SUPPORTED_CHAINS,
    EvmDataSource,
    SolanaDataSource,
    ManifestValidationError,
    WillowManifest,
    chain_family,
    evm_chain_id,
    from_evm_chain_id,
    is_supported_chain,
    parse_manifest,
    serialize_manifest,
    validate_manifest,
)


def good_manifest() -> WillowManifest:
    return WillowManifest(
        spec_version=MANIFEST_SPEC_VERSION,
        data_sources=[
            EvmDataSource(
                name="UniswapV3Pool",
                network="mainnet",
                address="0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640",
                abi="UniswapV3Pool",
                start_block=12369621,
                events=["Swap(address,address,int256,int256,uint160,uint128,int24)"],
            ),
        ],
    )


def solana_manifest() -> WillowManifest:
    return WillowManifest(
        spec_version=MANIFEST_SPEC_VERSION,
        data_sources=[
            SolanaDataSource(
                name="SplToken",
                network="solana-mainnet",
                program_id="TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                start_slot=100_000_000,
                instructions=["0x03"],
            ),
        ],
    )


# --- round-trip + normalization ---


def test_round_trip_canonical():
    bytes_ = serialize_manifest(good_manifest())
    parsed = parse_manifest(bytes_)
    assert parsed.spec_version == MANIFEST_SPEC_VERSION
    assert len(parsed.data_sources) == 1
    assert parsed.data_sources[0].network == "mainnet"


def test_normalizes_address_to_lowercase():
    m = good_manifest()
    m.data_sources[0].address = "0x88E6A0C2DDD26FEEB64F039A2C41296FCB3F5640"
    payload = serialize_manifest(m)
    assert b"0x88e6a0c2ddd26feeb64f039a2c41296fcb3f5640" in payload


def test_accepts_each_evm_canonical_chain():
    for chain in SUPPORTED_CHAINS:
        if chain_family(chain) != "evm":
            continue
        m = good_manifest()
        m.data_sources[0].network = chain
        validate_manifest(m)  # must not raise


# --- rejection cases ---


def test_rejects_unsupported_chain():
    m = good_manifest()
    m.data_sources[0].network = "frobnitz"
    with pytest.raises(ManifestValidationError):
        validate_manifest(m)


def test_rejects_legacy_ethereum_alias():
    m = good_manifest()
    m.data_sources[0].network = "ethereum"
    with pytest.raises(ManifestValidationError, match="not a canonical chain"):
        validate_manifest(m)


def test_rejects_evm_fields_on_solana_network():
    m = good_manifest()
    m.data_sources[0].network = "solana-mainnet"
    with pytest.raises(ManifestValidationError, match="Solana-family"):
        validate_manifest(m)


def test_rejects_wrong_spec_version():
    m = good_manifest()
    m.spec_version = "2.0.0"
    with pytest.raises(ManifestValidationError, match="spec_version"):
        validate_manifest(m)


def test_rejects_empty_data_sources():
    m = good_manifest()
    m.data_sources = []
    with pytest.raises(ManifestValidationError, match="at least one"):
        validate_manifest(m)


@pytest.mark.parametrize(
    "body", ["null", "[]", "42", '"string"']
)
def test_rejects_non_object_root(body):
    with pytest.raises(ManifestValidationError):
        parse_manifest(body)


def test_rejects_malformed_address():
    m = good_manifest()
    m.data_sources[0].address = "0x123"
    with pytest.raises(ManifestValidationError, match="40 hex"):
        validate_manifest(m)


def test_rejects_malformed_event_signature():
    m = good_manifest()
    m.data_sources[0].events = ["NotASignature"]
    with pytest.raises(ManifestValidationError, match=r"missing '\('"):
        validate_manifest(m)

    m.data_sources[0].events = ["Transfer(address, address, uint256)"]  # whitespace
    with pytest.raises(ManifestValidationError, match="invalid parameter type"):
        validate_manifest(m)


def test_rejects_name_with_bad_charset():
    m = good_manifest()
    m.data_sources[0].name = "Has Space"
    with pytest.raises(ManifestValidationError, match="alphanumeric"):
        validate_manifest(m)


def test_rejects_unknown_top_level_field():
    text = json.dumps({
        "spec_version": "1.0.0",
        "data_sources": [{
            "name": "T",
            "network": "mainnet",
            "address": "0x0000000000000000000000000000000000000000",
            "abi": "ERC20",
            "start_block": 0,
            "events": ["Transfer(address,address,uint256)"],
        }],
        "sneaky_extra": 1,
    })
    with pytest.raises(ManifestValidationError, match="unknown top-level"):
        parse_manifest(text)


def test_rejects_unknown_data_source_field():
    text = json.dumps({
        "spec_version": "1.0.0",
        "data_sources": [{
            "name": "T",
            "network": "mainnet",
            "address": "0x0000000000000000000000000000000000000000",
            "abi": "ERC20",
            "start_block": 0,
            "events": ["Transfer(address,address,uint256)"],
            "kind": "ethereum/contract",  # legacy subgraph shape
        }],
    })
    with pytest.raises(ManifestValidationError, match="unknown fields"):
        parse_manifest(text)


def test_attributes_errors_to_offending_field():
    m = good_manifest()
    m.data_sources.append(EvmDataSource(
        name="",  # invalid
        network="mainnet",
        address="0x0000000000000000000000000000000000000000",
        abi="ERC20",
        start_block=0,
        events=["Transfer(address,address,uint256)"],
    ))
    try:
        validate_manifest(m)
        pytest.fail("should have raised")
    except ManifestValidationError as e:
        assert e.field == "data_sources[1].name"


# --- SupportedChain helpers ---


def test_is_supported_chain_recognises_every_canonical_id():
    for chain in SUPPORTED_CHAINS:
        assert is_supported_chain(chain)


def test_is_supported_chain_rejects_aliases():
    assert not is_supported_chain("ethereum")
    assert not is_supported_chain("MAINNET")
    assert not is_supported_chain("")


def test_evm_chain_id_round_trip():
    for chain in SUPPORTED_CHAINS:
        if chain_family(chain) != "evm":
            assert evm_chain_id(chain) is None
            continue
        cid = evm_chain_id(chain)
        assert cid is not None
        assert from_evm_chain_id(cid) == chain


def test_chain_family_classifies():
    assert chain_family("mainnet") == "evm"
    assert chain_family("arbitrum-one") == "evm"
    assert chain_family("solana-mainnet") == "solana"


# --- Solana data sources ---


def test_solana_round_trip_native_spl():
    bytes_ = serialize_manifest(solana_manifest())
    parsed = parse_manifest(bytes_)
    assert isinstance(parsed.data_sources[0], SolanaDataSource)
    assert parsed.data_sources[0].program_id == "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    assert parsed.data_sources[0].instructions == ["0x03"]


def test_solana_accepts_anchor_eight_byte_discriminator():
    m = solana_manifest()
    m.data_sources[0].instructions = ["0xc1209b3341d69c81"]
    validate_manifest(m)


def test_solana_accepts_four_byte_system_tag():
    m = solana_manifest()
    m.data_sources[0].instructions = ["0x02000000"]
    validate_manifest(m)


def test_solana_accepts_mixed_length_discriminators():
    m = solana_manifest()
    m.data_sources[0].instructions = ["0x03", "0x07", "0xc1209b3341d69c81"]
    validate_manifest(m)


def test_solana_normalizes_discriminator_to_lowercase():
    m = solana_manifest()
    m.data_sources[0].instructions = ["0xABCD"]
    payload = serialize_manifest(m)
    assert b"0xabcd" in payload
    assert b"0xABCD" not in payload


def test_solana_rejects_odd_hex_discriminator():
    m = solana_manifest()
    m.data_sources[0].instructions = ["0x123"]
    with pytest.raises(ManifestValidationError, match="even.*non-zero number of hex"):
        validate_manifest(m)


def test_solana_rejects_empty_discriminator():
    m = solana_manifest()
    m.data_sources[0].instructions = ["0x"]
    with pytest.raises(ManifestValidationError, match="even.*non-zero number of hex"):
        validate_manifest(m)


def test_solana_rejects_discriminator_without_0x():
    m = solana_manifest()
    m.data_sources[0].instructions = ["03"]
    with pytest.raises(ManifestValidationError, match="even.*non-zero number of hex"):
        validate_manifest(m)


def test_solana_rejects_empty_instructions():
    m = solana_manifest()
    m.data_sources[0].instructions = []
    with pytest.raises(ManifestValidationError, match="at least one discriminator"):
        validate_manifest(m)


def test_solana_rejects_negative_start_slot():
    m = solana_manifest()
    m.data_sources[0].start_slot = -1
    with pytest.raises(ManifestValidationError, match="non-negative"):
        validate_manifest(m)


def test_solana_rejects_program_id_with_bad_charset():
    m = solana_manifest()
    m.data_sources[0].program_id = "Tokenkeg0feZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    with pytest.raises(ManifestValidationError, match="invalid base58"):
        validate_manifest(m)


def test_solana_rejects_program_id_with_wrong_length():
    m = solana_manifest()
    m.data_sources[0].program_id = "Token"
    with pytest.raises(ManifestValidationError, match="base58-encoded 32-byte"):
        validate_manifest(m)


def test_solana_mixed_evm_and_solana_manifest():
    m = WillowManifest(
        spec_version=MANIFEST_SPEC_VERSION,
        data_sources=good_manifest().data_sources + solana_manifest().data_sources,
    )
    validate_manifest(m)
    payload = serialize_manifest(m)
    parsed = parse_manifest(payload)
    assert isinstance(parsed.data_sources[0], EvmDataSource)
    assert isinstance(parsed.data_sources[1], SolanaDataSource)


def test_solana_rejects_unknown_data_source_field():
    text = json.dumps({
        "spec_version": "1.0.0",
        "data_sources": [{
            "name": "T",
            "network": "solana-mainnet",
            "program_id": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "start_slot": 0,
            "instructions": ["0x03"],
            "address": "0x0000000000000000000000000000000000000000",
        }],
    })
    with pytest.raises(ManifestValidationError, match="unknown fields"):
        parse_manifest(text)
