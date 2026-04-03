"""Tests for computed fields module."""

import pytest
from willow.computed_fields import (
    ComputedFieldDefinition,
    ComputedFieldRegistry,
    apply_computed_fields,
    apply_computed_fields_to_response,
    UNISWAP_V2_PAIR_FIELDS,
    UNISWAP_V2_TOKEN_FIELDS,
    UNISWAP_V2_AGGREGATION_FIELDS,
    GENERIC_AMM_PAIR_FIELDS,
    LENDING_PROTOCOL_FIELDS,
    LP_SHARE_FIELDS,
    global_computed_field_registry,
)
from willow.types import QueryResponse


class TestComputedFieldRegistry:
    """Test ComputedFieldRegistry class."""

    def test_register_and_get(self):
        """Test registering and retrieving fields."""
        registry = ComputedFieldRegistry()

        fields = [
            ComputedFieldDefinition(
                name="testField",
                description="A test field",
                dependencies=["input"],
                compute=lambda r: r.get("input", 0) * 2,
            )
        ]

        registry.register("dataset1", "dataset1", fields)

        result = registry.get("dataset1", "dataset1")
        assert result is not None
        assert len(result) == 1
        assert result[0].name == "testField"

    def test_get_unregistered_returns_none(self):
        """Test getting unregistered fields returns None."""
        registry = ComputedFieldRegistry()

        result = registry.get("nonexistent", "nonexistent")
        assert result is None

    def test_has_method(self):
        """Test has method."""
        registry = ComputedFieldRegistry()

        assert not registry.has("dataset1", "dataset1")

        registry.register("dataset1", "dataset1", [])

        assert registry.has("dataset1", "dataset1")
        assert not registry.has("dataset1", "dataset2")

    def test_unregister(self):
        """Test unregistering fields."""
        registry = ComputedFieldRegistry()

        registry.register("dataset1", "dataset1", [])
        assert registry.has("dataset1", "dataset1")

        result = registry.unregister("dataset1", "dataset1")
        assert result is True
        assert not registry.has("dataset1", "dataset1")

        # Unregistering again returns False
        result = registry.unregister("dataset1", "dataset1")
        assert result is False

    def test_clear(self):
        """Test clearing all registrations."""
        registry = ComputedFieldRegistry()

        registry.register("dataset1", "dataset1", [])
        registry.register("dataset2", "dataset2", [])

        registry.clear()

        assert not registry.has("dataset1", "dataset1")
        assert not registry.has("dataset2", "dataset2")


class TestApplyComputedFields:
    """Test apply_computed_fields function."""

    def test_applies_computed_fields_to_record(self):
        """Test that computed fields are added to records."""
        record = {"value": 10}

        fields = [
            ComputedFieldDefinition(
                name="doubled",
                description="Value doubled",
                dependencies=["value"],
                compute=lambda r: r.get("value", 0) * 2,
            )
        ]

        result = apply_computed_fields(record, fields)

        assert result["value"] == 10
        assert result["doubled"] == 20

    def test_preserves_original_fields(self):
        """Test that original fields are preserved."""
        record = {"a": 1, "b": 2, "c": 3}

        fields = [
            ComputedFieldDefinition(
                name="sum",
                description="Sum of a and b",
                dependencies=["a", "b"],
                compute=lambda r: r.get("a", 0) + r.get("b", 0),
            )
        ]

        result = apply_computed_fields(record, fields)

        assert result["a"] == 1
        assert result["b"] == 2
        assert result["c"] == 3
        assert result["sum"] == 3

    def test_skips_fields_with_missing_dependencies(self):
        """Test that fields with missing dependencies are skipped."""
        record = {"a": 1}

        fields = [
            ComputedFieldDefinition(
                name="computed",
                description="Requires a and b",
                dependencies=["a", "b"],
                compute=lambda r: r.get("a", 0) + r.get("b", 0),
            )
        ]

        result = apply_computed_fields(record, fields)

        assert "computed" not in result

    def test_handles_none_compute_result(self):
        """Test that None compute results don't add fields."""
        record = {"value": 0}

        fields = [
            ComputedFieldDefinition(
                name="divided",
                description="Division that might fail",
                dependencies=["value"],
                compute=lambda r: None if r.get("value") == 0 else 10 / r.get("value"),
            )
        ]

        result = apply_computed_fields(record, fields)

        assert "divided" not in result

    def test_multiple_computed_fields(self):
        """Test applying multiple computed fields."""
        record = {"x": 5, "y": 3}

        fields = [
            ComputedFieldDefinition(
                name="sum",
                description="Sum",
                dependencies=["x", "y"],
                compute=lambda r: r.get("x", 0) + r.get("y", 0),
            ),
            ComputedFieldDefinition(
                name="product",
                description="Product",
                dependencies=["x", "y"],
                compute=lambda r: r.get("x", 0) * r.get("y", 0),
            ),
            ComputedFieldDefinition(
                name="difference",
                description="Difference",
                dependencies=["x", "y"],
                compute=lambda r: r.get("x", 0) - r.get("y", 0),
            ),
        ]

        result = apply_computed_fields(record, fields)

        assert result["sum"] == 8
        assert result["product"] == 15
        assert result["difference"] == 2


class TestApplyComputedFieldsToResponse:
    """Test apply_computed_fields_to_response function."""

    def test_applies_to_all_documents(self):
        """Test that computed fields are applied to all documents."""
        response = QueryResponse(
            documents=[
                {"value": 10},
                {"value": 20},
                {"value": 30},
            ],
            total=3,
            limit=100,
            offset=0,
        )

        fields = [
            ComputedFieldDefinition(
                name="doubled",
                description="Value doubled",
                dependencies=["value"],
                compute=lambda r: r.get("value", 0) * 2,
            )
        ]

        result = apply_computed_fields_to_response(response, fields)

        assert len(result.documents) == 3
        assert result.documents[0]["doubled"] == 20
        assert result.documents[1]["doubled"] == 40
        assert result.documents[2]["doubled"] == 60

    def test_preserves_response_metadata(self):
        """Test that response metadata is preserved."""
        response = QueryResponse(
            documents=[{"value": 10}],
            total=100,
            limit=10,
            offset=5,
            proof="test-proof",
            verified_root_hash="abc123",
        )

        fields = [
            ComputedFieldDefinition(
                name="doubled",
                description="Value doubled",
                dependencies=["value"],
                compute=lambda r: r.get("value", 0) * 2,
            )
        ]

        result = apply_computed_fields_to_response(response, fields)

        assert result.total == 100
        assert result.limit == 10
        assert result.offset == 5
        assert result.proof == "test-proof"
        assert result.verified_root_hash == "abc123"


class TestUniswapV2PairFields:
    """Test Uniswap V2 pair computed fields."""

    def test_computes_token0_price(self):
        """Test token0 price computation."""
        record = {
            "reserve0": "1000000000000000000",  # 1 ETH
            "reserve1": "2000000000000000000",  # 2 USDC
        }

        result = apply_computed_fields(record, UNISWAP_V2_PAIR_FIELDS)

        assert "token0Price" in result
        assert result["token0Price"] == 2.0  # 2000/1000 = 2

    def test_computes_token1_price(self):
        """Test token1 price computation."""
        record = {
            "reserve0": "1000000000000000000",
            "reserve1": "2000000000000000000",
        }

        result = apply_computed_fields(record, UNISWAP_V2_PAIR_FIELDS)

        assert "token1Price" in result
        assert result["token1Price"] == 0.5  # 1000/2000 = 0.5

    def test_handles_decimal_adjustment(self):
        """Test decimal adjustment for different token decimals."""
        record = {
            "reserve0": "1000000000000000000",  # 1e18
            "reserve1": "1000000",               # 1e6 (USDC-like)
            "token0": {"decimals": 18},
            "token1": {"decimals": 6},
        }

        result = apply_computed_fields(record, UNISWAP_V2_PAIR_FIELDS)

        # With decimal adjustment, prices should be meaningful
        assert "token0Price" in result
        assert "token1Price" in result

    def test_handles_zero_reserve(self):
        """Test handling of zero reserves."""
        record = {
            "reserve0": "0",
            "reserve1": "1000000000000000000",
        }

        result = apply_computed_fields(record, UNISWAP_V2_PAIR_FIELDS)

        # Should not compute token0Price when reserve0 is 0
        assert "token0Price" not in result

    def test_handles_numeric_reserves(self):
        """Test handling of numeric (non-string) reserves."""
        record = {
            "reserve0": 1000,
            "reserve1": 2000,
        }

        result = apply_computed_fields(record, UNISWAP_V2_PAIR_FIELDS)

        assert result["token0Price"] == 2.0
        assert result["token1Price"] == 0.5


class TestUniswapV2TokenFields:
    """Test Uniswap V2 token computed fields."""

    def test_weth_derived_eth_is_one(self):
        """Test WETH derivedETH is 1.0."""
        record = {"isWeth": True}

        result = apply_computed_fields(record, UNISWAP_V2_TOKEN_FIELDS)

        assert result["derivedETH"] == 1.0

    def test_weth_by_symbol(self):
        """Test WETH detection by symbol."""
        record = {"symbol": "WETH"}

        result = apply_computed_fields(record, UNISWAP_V2_TOKEN_FIELDS)

        assert result["derivedETH"] == 1.0

    def test_computes_derived_eth_from_pair(self):
        """Test derivedETH computation from WETH pair reserves."""
        record = {
            "ethPairReserve0": "1000000000000000000",  # WETH
            "ethPairReserve1": "2000000000000000000",  # This token
            "ethPairToken0IsWeth": True,
        }

        result = apply_computed_fields(record, UNISWAP_V2_TOKEN_FIELDS)

        # Price = reserve0 / reserve1 = 0.5 ETH per token
        assert "derivedETH" in result
        assert result["derivedETH"] == 0.5

    def test_computes_derived_eth_when_weth_is_token1(self):
        """Test derivedETH when WETH is token1 in pair."""
        record = {
            "ethPairReserve0": "2000000000000000000",  # This token
            "ethPairReserve1": "1000000000000000000",  # WETH
            "ethPairToken0IsWeth": False,
        }

        result = apply_computed_fields(record, UNISWAP_V2_TOKEN_FIELDS)

        # Price = reserve1 / reserve0 = 0.5 ETH per token
        assert result["derivedETH"] == 0.5


class TestUniswapV2AggregationFields:
    """Test Uniswap V2 aggregation computed fields."""

    def test_computes_daily_volume_usd(self):
        """Test daily volume USD computation."""
        record = {
            "dailyVolumeETH": "10.5",
            "ethPriceUSD": "2000",
        }

        result = apply_computed_fields(record, UNISWAP_V2_AGGREGATION_FIELDS)

        assert result["dailyVolumeUSD"] == 21000.0

    def test_computes_total_liquidity_usd(self):
        """Test total liquidity USD computation."""
        record = {
            "totalLiquidityETH": "100.0",
            "ethPriceUSD": "2000",
        }

        result = apply_computed_fields(record, UNISWAP_V2_AGGREGATION_FIELDS)

        assert result["totalLiquidityUSD"] == 200000.0


class TestGenericAmmPairFields:
    """Test generic AMM pair fields."""

    def test_computes_prices_without_decimal_adjustment(self):
        """Test price computation without decimal adjustment."""
        record = {
            "reserve0": 1000,
            "reserve1": 2000,
        }

        result = apply_computed_fields(record, GENERIC_AMM_PAIR_FIELDS)

        assert result["token0Price"] == 2.0
        assert result["token1Price"] == 0.5


class TestLendingProtocolFields:
    """Test lending protocol computed fields."""

    def test_computes_utilization_rate(self):
        """Test utilization rate computation."""
        record = {
            "totalBorrows": "80000000",
            "totalSupply": "100000000",
        }

        result = apply_computed_fields(record, LENDING_PROTOCOL_FIELDS)

        assert result["utilizationRate"] == 0.8

    def test_computes_available_liquidity(self):
        """Test available liquidity computation."""
        record = {
            "totalBorrows": "80000000",
            "totalSupply": "100000000",
        }

        result = apply_computed_fields(record, LENDING_PROTOCOL_FIELDS)

        assert result["availableLiquidity"] == 20000000.0


class TestLPShareFields:
    """Test LP share computed fields."""

    def test_computes_share_of_pool(self):
        """Test share of pool computation."""
        record = {
            "userLPBalance": "100",
            "totalLPSupply": "1000",
        }

        result = apply_computed_fields(record, LP_SHARE_FIELDS)

        assert result["shareOfPool"] == 0.1

    def test_computes_user_token_amounts(self):
        """Test user token amount computation."""
        record = {
            "userLPBalance": "100",
            "totalLPSupply": "1000",
            "reserve0": "10000",
            "reserve1": "20000",
        }

        result = apply_computed_fields(record, LP_SHARE_FIELDS)

        assert result["userToken0Amount"] == 1000.0  # 10% of 10000
        assert result["userToken1Amount"] == 2000.0  # 10% of 20000


class TestGlobalRegistry:
    """Test global computed field registry."""

    def test_global_registry_exists(self):
        """Test that global registry is available."""
        assert global_computed_field_registry is not None
        assert isinstance(global_computed_field_registry, ComputedFieldRegistry)


class TestUniswapV2Integration:
    """Integration test for Uniswap V2 drop-in replacement scenario."""

    def test_full_pair_query_response(self):
        """Test that a full pair query response matches Graph API format."""
        response = QueryResponse(
            documents=[
                {
                    "id": "0x1234",
                    "reserve0": "1000000000000000000000",
                    "reserve1": "2500000000000000000000",
                    "token0": {"id": "0xweth", "symbol": "WETH", "decimals": 18},
                    "token1": {"id": "0xusdc", "symbol": "USDC", "decimals": 18},
                }
            ],
            total=1,
            limit=100,
            offset=0,
        )

        result = apply_computed_fields_to_response(response, UNISWAP_V2_PAIR_FIELDS)

        pair = result.documents[0]

        # Original fields preserved
        assert pair["id"] == "0x1234"
        assert pair["reserve0"] == "1000000000000000000000"
        assert pair["reserve1"] == "2500000000000000000000"

        # Computed fields added (matching Graph API)
        assert "token0Price" in pair
        assert "token1Price" in pair
        assert pair["token0Price"] == 2.5  # 2500/1000
        assert pair["token1Price"] == 0.4  # 1000/2500
