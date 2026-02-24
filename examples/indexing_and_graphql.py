"""
Willow Python SDK - Indexing and GraphQL Example

This example demonstrates blockchain indexing features:
1. Query indexed blockchain data via GraphQL
2. Check subgrove/indexer status
3. Verify indexing results with cryptographic proofs

Willow provides blockchain indexing with cryptographic proofs for every
query result, enabling trustless verification.

Prerequisites:
- pip install willow-sdk
- Run a local Willow node with indexing enabled
- Have a deployed subgrove
"""

import asyncio
from willow import (
    WillowClient,
    generate_did,
    WillowError,
)


async def main():
    print("Willow & GraphQL Demo")
    print("=" * 50)

    did_info = generate_did()

    async with WillowClient("http://localhost:3031") as client:
        # Authenticate
        await client.register_did(did_info["did_document"])
        await client.authenticate(
            did=did_info["did"],
            private_key_hex=did_info["private_key"],
            public_key_id=did_info["public_key_id"]
        )

        # 1. GraphQL Query
        print("\n1. GraphQL Query (Blockchain Data)")
        print("-" * 40)

        try:
            # Query indexed blockchain events
            result = await client.indexing.graphql_query(
                subgrove_id="uniswap-v3-mainnet",
                query="""
                    query GetRecentSwaps {
                        swaps(first: 5, orderBy: timestamp, orderDirection: desc) {
                            id
                            timestamp
                            amount0
                            amount1
                            pool {
                                token0 {
                                    symbol
                                }
                                token1 {
                                    symbol
                                }
                            }
                        }
                    }
                """,
                variables={}
            )
            print(f"Query result: {result}")
            if result.proof:
                print("Result includes cryptographic proof!")
        except WillowError as e:
            print(f"Query error: {e}")

        # 2. List Available Subgroves
        print("\n2. List Available Subgroves")
        print("-" * 40)

        try:
            subgroves = await client.indexing.list_subgroves()
            print(f"Found {len(subgroves)} subgroves:")
            for sg in subgroves[:5]:  # Show first 5
                print(f"  - {sg.id}: {sg.name}")
        except WillowError as e:
            print(f"Error: {e}")

        # 3. Get Subgrove Details
        print("\n3. Get Subgrove Details")
        print("-" * 40)

        try:
            subgrove = await client.indexing.get_subgrove("uniswap-v3-mainnet")
            print(f"Name: {subgrove.name}")
            print(f"Status: {subgrove.status}")
            print(f"Network: {subgrove.network}")
        except WillowError as e:
            print(f"Error: {e}")

        # 4. Check Indexing Status
        print("\n4. Check Indexing Status")
        print("-" * 40)

        try:
            status = await client.indexing.get_indexing_status("uniswap-v3-mainnet")
            print(f"Latest indexed block: {status.latest_block}")
            print(f"Chain head block: {status.chain_head_block}")
            print(f"Synced: {status.synced}")
        except WillowError as e:
            print(f"Error: {e}")

        # 5. List Indexers
        print("\n5. List Indexers")
        print("-" * 40)

        try:
            indexers = await client.indexing.list_indexers()
            print(f"Found {len(indexers)} indexers:")
            for idx in indexers[:5]:
                print(f"  - {idx.id}: {idx.status}")
        except WillowError as e:
            print(f"Error: {e}")

        # 6. Get Verification Stats
        print("\n6. Get Verification Stats")
        print("-" * 40)

        try:
            stats = await client.indexing.get_verification_stats()
            print(f"Total verifications: {stats.total_verifications}")
            print(f"Successful: {stats.successful}")
            print(f"Failed: {stats.failed}")
        except WillowError as e:
            print(f"Error: {e}")

    print("\n" + "=" * 50)
    print("Key Benefits of Willow:")
    print("- Cryptographic proofs for every query")
    print("- Trustless verification of indexed data")
    print("- Decentralized indexer network")
    print("- Automatic reorg handling")


if __name__ == "__main__":
    asyncio.run(main())
