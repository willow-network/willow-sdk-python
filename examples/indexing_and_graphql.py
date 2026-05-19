"""
Willow Python SDK - Indexing and GraphQL Example

Demonstrates blockchain indexing features:
1. Query indexed blockchain data via GraphQL
2. List subgroves
3. Get subgrove details
4. Check indexing status
5. List indexers
6. Get verification stats

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
    print("Willow Indexing & GraphQL Demo")
    print("=" * 50)

    did_info = generate_did()

    async with WillowClient("http://localhost:3031") as client:
        # Auth
        await client.register_did(did_info["did_document"])
        client.set_identity(
            did_info["did"],
            did_info["private_key"],
            did_info["public_key_id"],
        )

        # 1. GraphQL query against an indexed subgrove
        print("\n1. GraphQL Query (Blockchain Data)")
        print("-" * 40)
        try:
            result = await client.indexing.graphql_query(
                subgrove_id="uniswap-v3-mainnet",
                query="""
                    query GetRecentSwaps {
                        swaps(first: 5, orderBy: timestamp, orderDirection: desc) {
                            id
                            timestamp
                            amount0
                            amount1
                        }
                    }
                """,
                variables={},
            )
            print(f"Query result: {result}")
        except WillowError as e:
            print(f"Query error: {e}")

        # 2. List available subgroves
        print("\n2. List Available Subgroves")
        print("-" * 40)
        try:
            subgroves = await client.indexing.list_subgroves()
            print(f"Found {len(subgroves)} subgroves:")
            for sg in subgroves[:5]:
                print(f"  - {sg.subgrove_id}: {sg.name} ({sg.status})")
        except WillowError as e:
            print(f"Error: {e}")

        # 3. Get subgrove details
        print("\n3. Get Subgrove Details")
        print("-" * 40)
        try:
            subgrove = await client.indexing.get_subgrove("uniswap-v3-mainnet")
            print(f"ID: {subgrove.subgrove_id}")
            print(f"Name: {subgrove.name}")
            print(f"Status: {subgrove.status}")
            print(f"Latest block: {subgrove.latest_block}")
            print(f"Indexers: {len(subgrove.indexers)}")
        except WillowError as e:
            print(f"Error: {e}")

        # 4. Check indexing status
        print("\n4. Check Indexing Status")
        print("-" * 40)
        try:
            status = await client.indexing.get_indexing_status("uniswap-v3-mainnet")
            print(f"Synced block: {status.synced_block}")
            print(f"Target block: {status.target_block}")
            print(f"Progress: {status.progress_percentage:.1f}%")
            print(f"Status: {status.status}")
            if status.last_error:
                print(f"Last error: {status.last_error}")
        except WillowError as e:
            print(f"Error: {e}")

        # 5. List indexers
        print("\n5. List Indexers")
        print("-" * 40)
        try:
            indexers = await client.indexing.list_indexers()
            print(f"Found {len(indexers)} indexers:")
            for idx in indexers[:5]:
                print(f"  - {idx.indexer_did[:24]}...: {idx.status}")
                print(f"    stake={idx.stake_amount}, score={idx.performance_score:.2f}")
        except WillowError as e:
            print(f"Error: {e}")

        # 6. Get verification stats
        print("\n6. Get Verification Stats")
        print("-" * 40)
        try:
            stats = await client.indexing.get_verification_stats()
            print(f"Total blocks: {stats.total_blocks}")
            print(f"Verified: {stats.verified_blocks}")
            print(f"Unverified: {stats.unverified_blocks}")
            print(f"Finalized: {stats.finalized_blocks}")
            print(f"Failed: {stats.failed_blocks}")
            print(f"Verification rate: {stats.verification_rate:.1%}")
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
