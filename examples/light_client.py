"""
Willow Python SDK - Light Client Example

This example demonstrates the light client for trustless verification:
1. Configure the light client
2. Verify block headers against validators
3. Verify proofs against consensus state

The light client implements CometBFT light client protocol:
- Verifies 2/3+ validator signatures
- Validates header chain progression
- Provides trusted app_hash for proof verification

Prerequisites:
- pip install willow-sdk
- Run a local Willow node
"""

import asyncio
from willow import (
    LightClient,
    LightClientConfig,
    LightClientConfigBuilder,
    WillowError,
)


async def main():
    print("Willow Light Client Demo")
    print("=" * 50)

    # 1. Create Light Client with Config Builder
    print("\n1. Configure Light Client")
    print("-" * 40)

    config = (
        LightClientConfigBuilder()
        .with_rpc_endpoints([
            "http://localhost:26657",
            "http://localhost:26658",
            "http://localhost:26659",
        ])
        .with_trust_threshold(2, 3)  # Require 2/3+ signatures
        .with_trusting_period(86400)  # 24 hours in seconds
        .with_clock_drift(10)  # 10 second clock drift tolerance
        .build()
    )

    print(f"RPC endpoints: {len(config.rpc_endpoints)}")
    print(f"Trust threshold: {config.trust_threshold}")
    print(f"Trusting period: {config.trusting_period}s")
    print(f"Clock drift: {config.clock_drift}s")

    # 2. Initialize Light Client
    print("\n2. Initialize Light Client")
    print("-" * 40)

    try:
        async with LightClient(config) as light_client:
            # 3. Get Latest Trusted Header
            print("\n3. Get Latest Trusted Header")
            print("-" * 40)

            try:
                header = await light_client.get_latest_header()
                print(f"Height: {header.height}")
                print(f"Time: {header.time}")
                print(f"App Hash: {header.app_hash[:32]}...")
                print(f"Chain ID: {header.chain_id}")
            except Exception as e:
                print(f"Error: {e}")

            # 4. Verify Specific Height
            print("\n4. Verify Block at Height")
            print("-" * 40)

            try:
                block = await light_client.verify_to_height(1)
                print(f"Verified block at height 1")
                print(f"App Hash: {block.app_hash[:32]}...")
            except Exception as e:
                print(f"Error: {e}")

            # 5. Get Trusted App Hash for Proof Verification
            print("\n5. Get Trusted App Hash")
            print("-" * 40)

            try:
                app_hash = await light_client.get_trusted_app_hash()
                print(f"Trusted app hash: {app_hash[:32]}...")
                print("Use this to verify GroveDB proofs!")
            except Exception as e:
                print(f"Error: {e}")

            # 6. Verify Proof Against Consensus
            print("\n6. Verify Proof Against Consensus")
            print("-" * 40)

            sample_proof = "00" + "ff" * 32  # Invalid for demo
            try:
                result = await light_client.verify_inclusion_proof(
                    proof_hex=sample_proof,
                    path=["apps", "my-app", "users"],
                    key="user-123"
                )
                print(f"Proof valid: {result.valid}")
            except Exception as e:
                print(f"Error (expected for invalid proof): {e}")

    except Exception as e:
        print(f"Light client error: {e}")

    # 7. Alternative: Direct Configuration
    print("\n7. Direct Configuration")
    print("-" * 40)

    direct_config = LightClientConfig(
        rpc_endpoints=["http://localhost:26657"],
        trust_threshold=(2, 3),
        trusting_period=86400,
        clock_drift=10,
    )
    print(f"Created config with {len(direct_config.rpc_endpoints)} endpoints")

    print("\n" + "=" * 50)
    print("Light Client Security Model:")
    print("1. Fetch block headers from RPC endpoints")
    print("2. Verify 2/3+ validator signatures")
    print("3. Validate header chain (heights, times)")
    print("4. Extract app_hash (GroveDB root)")
    print("5. Verify proofs against trusted app_hash")
    print("\nThis provides full trustless verification!")


if __name__ == "__main__":
    asyncio.run(main())
