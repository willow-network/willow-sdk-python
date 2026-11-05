"""
Willow Python SDK - Quickstart Example

Demonstrates the core workflow:
1. Generate a DID (identity)
2. Connect to a Willow node
3. Set the identity for per-request signing
4. Register the DID
5. Register a subgrove, funded from the DID's balance
6. Store data, and query it (query results are not verified)

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
        # The DID must first be pre-funded with the DID and subgrove
        # registration fees plus the subgrove's funding (see
        # client.token.get_fee_schedule()). A write returns once CheckTx
        # accepts it: wait for the registration to land before the DID signs
        # anything else.
        print("\nRegistering DID...")
        registration = await client.register_did(did_info["did_document"])
        await client.wait_until_landed(registration)
        print("  DID registered")

        # 5. Register a subgrove the DID owns and writes to. StoreData is
        # paid from the subgrove's balance, so fund it at registration (1
        # WILL, 10**18 base units, from the DID's balance), and wait for it
        # to land before storing into it.
        print("\nRegistering subgrove...")
        subgrove = await client.registration.register_subgrove({
            "dataset_id": SUBGROVE,
            "name": "Quickstart Users",
            "schema": {
                "version": 1,
                "fields": {"name": {"type": "string"}, "email": {"type": "string"}},
            },
            "owner_did": did_info["did"],
            "writers": [did_info["did"]],
            "readers": [],
            "initial_funding": 10**18,
        })
        await client.wait_until_landed(subgrove)
        print(f"  Subgrove {SUBGROVE} registered")

        # 6. Store data, and wait for it to land before reading it.
        print("\nStoring data...")
        writes = await client.data.store(
            SUBGROVE,
            {"user_1": {"name": "Alice", "email": "alice@example.com"}},
        )
        await client.wait_until_landed(writes)
        print("  Data stored")

        # 7. Query data. Query results are not verified; client.data.get
        #    verifies a single key, given a consensus_rpc_url to check
        #    against (see data_operations.py).
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
