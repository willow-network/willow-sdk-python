"""
Willow Python SDK - Light Client Example

Demonstrates the CometBFT light client's interface:
1. Configure the light client with the fluent builder
2. Initialize with trust-on-first-use (or a header you pass it)
3. Read the root hash (app_hash) of the latest header it holds
4. Check a later header (which never verifies)

What it checks: trust-on-first-use holds the first header its endpoints
serve, as served. The SDK does not verify CometBFT commit signatures, so
`verify_header` never reports a header verified, and a proof checked against
a header it holds is only as trustworthy as that header's source.
`WillowClient.data.get` doesn't use it: it reads headers from the
`consensus_rpc_url` you configure, and trusts that node.

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

            # 3. The root hash (app_hash) of the latest header it holds
            print("\n3. Root Hash (trusted on first use, not verified)")
            print("-" * 40)
            try:
                root_hash = await light_client.get_verified_root_hash()
                print(f"Latest held app_hash: {root_hash[:32]}...")
            except WillowError as e:
                print(f"Error: {e}")

            # 4. Fetch a header by height and check it: it never verifies
            print("\n4. Fetch and Check a Header")
            print("-" * 40)
            try:
                header = await light_client.get_header_by_height(1)
                if header:
                    result = await light_client.verify_header(header)
                    print(f"Height 1 verified: {result.success}")
                    if not result.success and result.error:
                        print(f"Reason: {result.error}")
                else:
                    # get_header_by_height returns only a header the client
                    # holds; one it fetches is never verified, so it isn't.
                    print("The client holds no header at height 1: it trusted only the "
                          "latest on first use, and a fetched header is never verified.")
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
    print("A trusted header's app_hash is the root of the state after the block")
    print("before it: a proof of the state after block H checks against header H+1.")


if __name__ == "__main__":
    asyncio.run(main())
