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
        # 3. Set identity (synchronous). It signs each transaction and each
        # authenticated request; there is no server session.
        print("\nSetting identity...")
        client.set_identity(
            did_info["did"],
            did_info["private_key"],
            did_info["public_key_id"],
        )
        print("  Identity set")

        # 4. Register the DID on the network (a RegisterDid transaction).
        # The DID must first be pre-funded with the registration fee. A write
        # returns once CheckTx accepts it: wait for the registration to land
        # before the DID signs anything else.
        print("\nRegistering DID...")
        registration = await client.register_did(did_info["did_document"])
        await client.wait_until_landed(registration)
        print("  DID registered")

        # 5. Store data (automatic proof verification on reads).
        # In a real app you'd register the subgrove/dataset first; see
        # app_registration.py.
        print("\nStoring data...")
        try:
            await client.data.store(
                SUBGROVE,
                {"user_1": {"name": "Alice", "email": "alice@example.com"}},
            )
            print("  Data stored successfully")
        except WillowError as e:
            print(f"  Note: {e} (subgrove may need registration first)")

        # 6. Query data. Query results are not verified; client.data.get
        #    verifies a single key.
        print("\nQuerying data...")
        try:
            result = await client.data.query_unverified(
                SUBGROVE,
                {"filters": {"name": "Alice"}},
            )
            print(f"  Found {len(result.documents)} documents (unverified)")
        except WillowError as e:
            print(f"  Note: {e}")

    print("\nQuickstart complete!")


if __name__ == "__main__":
    asyncio.run(main())
