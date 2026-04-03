"""Computed Fields Module.

This module provides SDK-layer computation of derived fields from proven data.
It enables drop-in compatibility with The Graph's query interfaces by computing
derived values (like price ratios) from cryptographically proven base data.

Design Philosophy:
- GKR circuits prove the underlying data (reserves, volumes, balances)
- Division and other derived calculations are done client-side
- Same trust model: proven inputs + deterministic computation = trustworthy outputs
- Same API: queries return the same fields The Graph would return

Example:
    >>> from willow import WillowClient
    >>> from willow.computed_fields import UNISWAP_V2_PAIR_FIELDS
    >>>
    >>> async with WillowClient("http://localhost:3031") as client:
    ...     # Register Uniswap V2 computed fields
    ...     client.register_computed_fields('pairs', UNISWAP_V2_PAIR_FIELDS)
    ...
    ...     # Query returns computed prices alongside proven reserves
    ...     result = await client.data.query('pairs', {'filters': {'id': '0x...'}})
    ...     # result.documents[0] contains:
    ...     # - reserve0, reserve1 (proven by GKR circuit)
    ...     # - token0Price, token1Price (computed from proven reserves)
"""

from typing import Any, Callable, Dict, List, Optional, Union

from .types import QueryResponse


# Type alias for compute functions
ComputeFunction = Callable[[Dict[str, Any]], Optional[Union[int, float, str]]]


class ComputedFieldDefinition:
    """Definition of a single computed field.

    Attributes:
        name: The field name in the output record.
        description: Human-readable description of what this field represents.
        dependencies: The proven fields this computation depends on.
        compute: The computation function.
    """

    def __init__(
        self,
        name: str,
        description: str,
        dependencies: List[str],
        compute: ComputeFunction,
    ):
        """Initialize a computed field definition.

        Args:
            name: The field name in the output record.
            description: Human-readable description of what this field represents.
            dependencies: The proven fields this computation depends on.
            compute: The computation function that takes a record dict and returns
                     the computed value or None if computation cannot be performed.
        """
        self.name = name
        self.description = description
        self.dependencies = dependencies
        self.compute = compute


# Type alias for a set of computed field definitions
ComputedFieldSet = List[ComputedFieldDefinition]


class ComputedFieldRegistry:
    """Registry of computed fields by app/dataset.

    This class manages registration and retrieval of computed field definitions
    for different app/dataset combinations.

    Example:
        >>> registry = ComputedFieldRegistry()
        >>> registry.register('pairs', UNISWAP_V2_PAIR_FIELDS)
        >>> fields = registry.get('pairs')
    """

    def __init__(self):
        """Initialize an empty registry."""
        self._registry: Dict[str, ComputedFieldSet] = {}

    def register(self, dataset_id: str, fields: ComputedFieldSet) -> None:
        """Register computed fields for a specific dataset.

        Args:
            dataset_id: The dataset ID.
            fields: The computed field definitions.
        """
        key = dataset_id
        self._registry[key] = fields

    def get(self, dataset_id: str) -> Optional[ComputedFieldSet]:
        """Get computed fields for a specific app/dataset.

        Args:
            dataset_id: The dataset ID.

        Returns:
            The computed field set or None if not registered.
        """
        key = dataset_id
        return self._registry.get(key)

    def has(self, dataset_id: str) -> bool:
        """Check if computed fields are registered for an app/dataset.

        Args:
            dataset_id: The dataset ID.

        Returns:
            True if fields are registered, False otherwise.
        """
        key = dataset_id
        return key in self._registry

    def unregister(self, dataset_id: str) -> bool:
        """Remove computed fields for an app/dataset.

        Args:
            dataset_id: The dataset ID.

        Returns:
            True if fields were removed, False if they weren't registered.
        """
        key = dataset_id
        if key in self._registry:
            del self._registry[key]
            return True
        return False

    def clear(self) -> None:
        """Clear all registered computed fields."""
        self._registry.clear()


def _parse_numeric(value: Any) -> Optional[float]:
    """Safely parse a numeric value from various formats.

    Handles strings (including BigInt-like strings), numbers, and int.

    Args:
        value: The value to parse.

    Returns:
        The numeric value as float, or None if parsing fails.
    """
    if value is None:
        return None

    if isinstance(value, (int, float)):
        return float(value)

    if isinstance(value, str):
        # Handle hex strings
        if value.startswith("0x"):
            try:
                return float(int(value, 16))
            except ValueError:
                return None
        # Handle decimal strings (potentially very large)
        try:
            return float(value)
        except ValueError:
            return None

    return None


def apply_computed_fields(
    record: Dict[str, Any],
    fields: ComputedFieldSet,
) -> Dict[str, Any]:
    """Apply computed fields to a single record.

    Args:
        record: The data record with proven fields.
        fields: The computed field definitions to apply.

    Returns:
        A new record with computed fields added.
    """
    result = dict(record)

    for field in fields:
        # Check if all dependencies are present
        has_dependencies = all(
            record.get(dep) is not None
            for dep in field.dependencies
        )

        if has_dependencies:
            computed = field.compute(record)
            if computed is not None:
                result[field.name] = computed

    return result


def apply_computed_fields_to_response(
    response: QueryResponse,
    fields: ComputedFieldSet,
) -> QueryResponse:
    """Apply computed fields to a query response.

    Creates a new QueryResponse with computed fields added to documents.

    Args:
        response: The query response with proven data.
        fields: The computed field definitions to apply.

    Returns:
        A new response with computed fields added to documents.
    """
    new_documents = [
        apply_computed_fields(doc, fields)
        for doc in response.documents
    ]

    return QueryResponse(
        documents=new_documents,
        total=response.total,
        limit=response.limit,
        offset=response.offset,
        proof=response.proof,
        verified_root_hash=response.verified_root_hash,
    )


# ============================================================================
# Pre-built Field Sets for Common Protocols
# ============================================================================


def _compute_token0_price(record: Dict[str, Any]) -> Optional[float]:
    """Compute token0 price from reserves."""
    reserve0 = _parse_numeric(record.get("reserve0"))
    reserve1 = _parse_numeric(record.get("reserve1"))

    if reserve0 is None or reserve1 is None:
        return None

    # Avoid division by zero
    if reserve0 == 0:
        return None

    # Apply decimal adjustment if available
    token0 = record.get("token0") or {}
    token1 = record.get("token1") or {}
    decimals0 = _parse_numeric(token0.get("decimals")) or 18
    decimals1 = _parse_numeric(token1.get("decimals")) or 18
    decimal_adjustment = 10 ** (decimals0 - decimals1)

    return (reserve1 / reserve0) * decimal_adjustment


def _compute_token1_price(record: Dict[str, Any]) -> Optional[float]:
    """Compute token1 price from reserves."""
    reserve0 = _parse_numeric(record.get("reserve0"))
    reserve1 = _parse_numeric(record.get("reserve1"))

    if reserve0 is None or reserve1 is None:
        return None

    # Avoid division by zero
    if reserve1 == 0:
        return None

    # Apply decimal adjustment if available
    token0 = record.get("token0") or {}
    token1 = record.get("token1") or {}
    decimals0 = _parse_numeric(token0.get("decimals")) or 18
    decimals1 = _parse_numeric(token1.get("decimals")) or 18
    decimal_adjustment = 10 ** (decimals1 - decimals0)

    return (reserve0 / reserve1) * decimal_adjustment


UNISWAP_V2_PAIR_FIELDS: ComputedFieldSet = [
    ComputedFieldDefinition(
        name="token0Price",
        description="Price of token0 in terms of token1 (reserve1 / reserve0)",
        dependencies=["reserve0", "reserve1"],
        compute=_compute_token0_price,
    ),
    ComputedFieldDefinition(
        name="token1Price",
        description="Price of token1 in terms of token0 (reserve0 / reserve1)",
        dependencies=["reserve0", "reserve1"],
        compute=_compute_token1_price,
    ),
]
"""Uniswap V2 Pair computed fields.

These fields are computed from proven reserve data to match
The Graph's Uniswap V2 subgraph schema.

Proven fields required:
- reserve0: Token 0 reserve amount
- reserve1: Token 1 reserve amount
- token0.decimals: Token 0 decimals (optional, defaults to 18)
- token1.decimals: Token 1 decimals (optional, defaults to 18)
"""


def _compute_derived_eth(record: Dict[str, Any]) -> Optional[float]:
    """Compute derived ETH price for a token."""
    # If this is WETH itself, return 1
    if record.get("isWeth") is True or record.get("symbol") == "WETH":
        return 1.0

    # For other tokens, we need the WETH pair reserves
    reserve0 = _parse_numeric(record.get("ethPairReserve0"))
    reserve1 = _parse_numeric(record.get("ethPairReserve1"))

    # If we don't have pair reserves, we can't compute derivedETH
    if reserve0 is None or reserve1 is None:
        return None

    # Determine which reserve is WETH
    token0_is_weth = record.get("ethPairToken0IsWeth") is True

    if token0_is_weth:
        # WETH is token0, so price = reserve0 / reserve1
        if reserve1 == 0:
            return None
        return reserve0 / reserve1
    else:
        # WETH is token1, so price = reserve1 / reserve0
        if reserve0 == 0:
            return None
        return reserve1 / reserve0


UNISWAP_V2_TOKEN_FIELDS: ComputedFieldSet = [
    ComputedFieldDefinition(
        name="derivedETH",
        description="Price of token in ETH (derived from WETH pair reserves)",
        # Empty dependencies - we handle the logic internally since WETH is a special case
        dependencies=[],
        compute=_compute_derived_eth,
    ),
]
"""Uniswap V2 Token computed fields.

These fields compute derived ETH prices from proven stablecoin pool reserves.

Proven fields required:
- For WETH: Just use 1.0 as derivedETH (detected by isWeth or symbol)
- For tokens: ethPairReserve0, ethPairReserve1 (reserves from WETH pair)
"""


def _compute_daily_volume_usd(record: Dict[str, Any]) -> Optional[float]:
    """Compute daily volume in USD."""
    volume_eth = _parse_numeric(record.get("dailyVolumeETH"))
    eth_price = _parse_numeric(record.get("ethPriceUSD"))

    if volume_eth is None or eth_price is None:
        return None

    return volume_eth * eth_price


def _compute_total_liquidity_usd(record: Dict[str, Any]) -> Optional[float]:
    """Compute total liquidity in USD."""
    liquidity_eth = _parse_numeric(record.get("totalLiquidityETH"))
    eth_price = _parse_numeric(record.get("ethPriceUSD"))

    if liquidity_eth is None or eth_price is None:
        return None

    return liquidity_eth * eth_price


UNISWAP_V2_AGGREGATION_FIELDS: ComputedFieldSet = [
    ComputedFieldDefinition(
        name="dailyVolumeUSD",
        description="Daily volume in USD (dailyVolumeETH * ethPriceUSD)",
        dependencies=["dailyVolumeETH", "ethPriceUSD"],
        compute=_compute_daily_volume_usd,
    ),
    ComputedFieldDefinition(
        name="totalLiquidityUSD",
        description="Total liquidity in USD (totalLiquidityETH * ethPriceUSD)",
        dependencies=["totalLiquidityETH", "ethPriceUSD"],
        compute=_compute_total_liquidity_usd,
    ),
]
"""Uniswap V2 daily/hourly data computed fields.

These compute USD values from proven ETH amounts and ETH price.
"""


def _compute_generic_token0_price(record: Dict[str, Any]) -> Optional[float]:
    """Compute token0 price without decimal adjustment."""
    reserve0 = _parse_numeric(record.get("reserve0"))
    reserve1 = _parse_numeric(record.get("reserve1"))

    if reserve0 is None or reserve1 is None or reserve0 == 0:
        return None

    return reserve1 / reserve0


def _compute_generic_token1_price(record: Dict[str, Any]) -> Optional[float]:
    """Compute token1 price without decimal adjustment."""
    reserve0 = _parse_numeric(record.get("reserve0"))
    reserve1 = _parse_numeric(record.get("reserve1"))

    if reserve0 is None or reserve1 is None or reserve1 == 0:
        return None

    return reserve0 / reserve1


GENERIC_AMM_PAIR_FIELDS: ComputedFieldSet = [
    ComputedFieldDefinition(
        name="token0Price",
        description="Price of token0 in terms of token1",
        dependencies=["reserve0", "reserve1"],
        compute=_compute_generic_token0_price,
    ),
    ComputedFieldDefinition(
        name="token1Price",
        description="Price of token1 in terms of token0",
        dependencies=["reserve0", "reserve1"],
        compute=_compute_generic_token1_price,
    ),
]
"""Generic AMM pair fields (works for Uniswap V2, Sushiswap, etc.).

A simplified version of pair fields without decimal adjustment.
"""


def _compute_utilization_rate(record: Dict[str, Any]) -> Optional[float]:
    """Compute utilization rate."""
    borrows = _parse_numeric(record.get("totalBorrows"))
    supply = _parse_numeric(record.get("totalSupply"))

    if borrows is None or supply is None or supply == 0:
        return None

    return borrows / supply


def _compute_available_liquidity(record: Dict[str, Any]) -> Optional[float]:
    """Compute available liquidity."""
    borrows = _parse_numeric(record.get("totalBorrows"))
    supply = _parse_numeric(record.get("totalSupply"))

    if borrows is None or supply is None:
        return None

    return supply - borrows


LENDING_PROTOCOL_FIELDS: ComputedFieldSet = [
    ComputedFieldDefinition(
        name="utilizationRate",
        description="Utilization rate (totalBorrows / totalSupply)",
        dependencies=["totalBorrows", "totalSupply"],
        compute=_compute_utilization_rate,
    ),
    ComputedFieldDefinition(
        name="availableLiquidity",
        description="Available liquidity (totalSupply - totalBorrows)",
        dependencies=["totalBorrows", "totalSupply"],
        compute=_compute_available_liquidity,
    ),
]
"""Lending protocol fields (for Aave, Compound, etc.).

Computes utilization rate from proven supply and borrow amounts.
"""


def _compute_share_of_pool(record: Dict[str, Any]) -> Optional[float]:
    """Compute user share of pool."""
    user_balance = _parse_numeric(record.get("userLPBalance"))
    total_supply = _parse_numeric(record.get("totalLPSupply"))

    if user_balance is None or total_supply is None or total_supply == 0:
        return None

    return user_balance / total_supply


def _compute_user_token0_amount(record: Dict[str, Any]) -> Optional[float]:
    """Compute user share of token0."""
    user_balance = _parse_numeric(record.get("userLPBalance"))
    total_supply = _parse_numeric(record.get("totalLPSupply"))
    reserve0 = _parse_numeric(record.get("reserve0"))

    if (
        user_balance is None
        or total_supply is None
        or reserve0 is None
        or total_supply == 0
    ):
        return None

    return (user_balance / total_supply) * reserve0


def _compute_user_token1_amount(record: Dict[str, Any]) -> Optional[float]:
    """Compute user share of token1."""
    user_balance = _parse_numeric(record.get("userLPBalance"))
    total_supply = _parse_numeric(record.get("totalLPSupply"))
    reserve1 = _parse_numeric(record.get("reserve1"))

    if (
        user_balance is None
        or total_supply is None
        or reserve1 is None
        or total_supply == 0
    ):
        return None

    return (user_balance / total_supply) * reserve1


LP_SHARE_FIELDS: ComputedFieldSet = [
    ComputedFieldDefinition(
        name="shareOfPool",
        description="User share of pool (userLPBalance / totalLPSupply)",
        dependencies=["userLPBalance", "totalLPSupply"],
        compute=_compute_share_of_pool,
    ),
    ComputedFieldDefinition(
        name="userToken0Amount",
        description="User share of token0 (shareOfPool * reserve0)",
        dependencies=["userLPBalance", "totalLPSupply", "reserve0"],
        compute=_compute_user_token0_amount,
    ),
    ComputedFieldDefinition(
        name="userToken1Amount",
        description="User share of token1 (shareOfPool * reserve1)",
        dependencies=["userLPBalance", "totalLPSupply", "reserve1"],
        compute=_compute_user_token1_amount,
    ),
]
"""LP share computation fields."""


# Global registry instance
global_computed_field_registry = ComputedFieldRegistry()


__all__ = [
    # Classes
    "ComputedFieldDefinition",
    "ComputedFieldSet",
    "ComputedFieldRegistry",
    "ComputeFunction",
    # Functions
    "apply_computed_fields",
    "apply_computed_fields_to_response",
    # Pre-built field sets
    "UNISWAP_V2_PAIR_FIELDS",
    "UNISWAP_V2_TOKEN_FIELDS",
    "UNISWAP_V2_AGGREGATION_FIELDS",
    "GENERIC_AMM_PAIR_FIELDS",
    "LENDING_PROTOCOL_FIELDS",
    "LP_SHARE_FIELDS",
    # Global registry
    "global_computed_field_registry",
]
