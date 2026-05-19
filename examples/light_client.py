"""
Willow Python SDK - Light Client Example

Demonstrates the CometBFT light client for trustless verification:
1. Configure the light client with the fluent builder
2. Initialize with trust-on-first-use (or a hardcoded trusted header)
3. Fetch and verify the current verified root hash (app_hash)
4. Verify subsequent headers against the trusted set

Security model:
- Verifies 2/3+ validator signatures
- Validates header chain (heights, times)
- Extracts app_hash for GroveDB proof verification

Prerequisites:
- pip install willow-sdk
- Run a local Willow node
"""

import asyncio
from willow import (
    LightClient,
    LightClientConfigBuilder,
    LightClientConfig,
    WillowError,
)


CHAIN_ID = "willow-devnet"


async def main():
    print("Willow Light Client Demo")
    print("=" * 50)

    # 1. Configure the light client
    print("\n1. Configure Light Client")
    print("-" * 40)

    config = (
        LightClientConfigBuilder(CHAIN_ID)
        .validator_endpoints([
            "http://localhost:26657",
            "http://localhost:26658",
            "http://localhost:26659",
        ])
        .trust_threshold(2, 3)
        .trusting_period_hours(24)
        .max_clock_drift_secs(10)
        .min_validators_for_consensus(2)
        .build()
    )

    print(f"Chain ID: {config.chain_id}")
    print(f"Validator endpoints: {len(config.validator_endpoints)}")
    print(f"Trust threshold: {config.trust_threshold.numerator}/{config.trust_threshold.denominator}")
    print(f"Trusting period: {config.trusting_period_secs}s")
    print(f"Max clock drift: {config.max_clock_drift_secs}s")

    # 2. Initialize and use the light client
    print("\n2. Initialize Light Client (trust-on-first-use)")
    print("-" * 40)

    try:
        async with LightClient(config) as light_client:
            await light_client.initialize_with_trust_on_first_use()
            print("Light client initialized")

            # 3. Get the verified root hash (app_hash)
            print("\n3. Verified Root Hash")
            print("-" * 40)
            try:
                root_hash = await light_client.get_verified_root_hash()
                print(f"Verified app_hash: {root_hash[:32]}...")
                print("Use this to verify GroveDB proofs.")
            except WillowError as e:
                print(f"Error: {e}")

            # 4. Fetch a header by height and verify it
            print("\n4. Fetch and Verify a Header")
            print("-" * 40)
            try:
                header = await light_client.get_header_by_height(1)
                if header:
                    result = await light_client.verify_header(header)
                    print(f"Height 1 verified: {result.success}")
                    if not result.success and result.error:
                        print(f"Reason: {result.error}")
                else:
                    print("No header at height 1 yet.")
            except Exception as e:
                print(f"Error: {e}")
    except Exception as e:
        print(f"Light client error: {e}")

    # 5. Alternative: build the config dataclass directly
    print("\n5. Direct Configuration")
    print("-" * 40)

    direct_config = LightClientConfig(
        chain_id=CHAIN_ID,
        validator_endpoints=["http://localhost:26657"],
    )
    print(f"Created config with {len(direct_config.validator_endpoints)} endpoint(s)")

    print("\n" + "=" * 50)
    print("Light Client Security Model:")
    print("1. Fetch block headers from validator RPC endpoints")
    print("2. Verify 2/3+ validator signatures")
    print("3. Validate header chain (heights, times)")
    print("4. Extract app_hash (GroveDB root)")
    print("5. Verify proofs against trusted app_hash")


if __name__ == "__main__":
    asyncio.run(main())
