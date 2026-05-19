"""
Willow Python SDK - Quickstart Example

Demonstrates the core workflow:
1. Generate a DID (identity)
2. Connect to a Willow node
3. Register the DID
4. Set the identity for per-request signing
5. Store and query data with automatic proof verification

Prerequisites:
- pip install willow-sdk
- Run a local Willow node: ./scripts/start_node.sh
"""

import asyncio
from willow import (
    WillowClient,
    generate_did,
    WillowError,
)


SUBGROVE = "quickstart-users"


async def main():
    # 1. Generate a new DID (Decentralized Identifier)
    print("Generating DID...")
    did_info = generate_did(algorithm="Ed25519")
    print(f"  DID: {did_info['did']}")

    # 2. Connect to Willow node
    async with WillowClient("http://localhost:3031") as client:
        # 3. Register the DID on the network
        print("\nRegistering DID...")
        await client.register_did(did_info["did_document"])
        print("  DID registered successfully")

        # 4. Set identity for per-request signing (synchronous).
        # Each authenticated call signs with this key; there is no server session.
        print("\nSetting identity...")
        client.set_identity(
            did_info["did"],
            did_info["private_key"],
            did_info["public_key_id"],
        )
        print("  Identity set")

        # 5. Store data (automatic proof verification on reads).
        # In a real app you'd register the subgrove/dataset first; see
        # app_registration.py.
        print("\nStoring data...")
        try:
            await client.data.store(
                SUBGROVE,
                {"name": "Alice", "email": "alice@example.com"},
            )
            print("  Data stored successfully")
        except WillowError as e:
            print(f"  Note: {e} (subgrove may need registration first)")

        # 6. Query data (automatic proof verification).
        print("\nQuerying data...")
        try:
            result = await client.data.query(
                SUBGROVE,
                {"filters": {"name": "Alice"}},
            )
            print(f"  Found {len(result.documents)} documents")
            if result.proof:
                print("  Proof verified automatically")
        except WillowError as e:
            print(f"  Note: {e}")

    print("\nQuickstart complete!")


if __name__ == "__main__":
    asyncio.run(main())
