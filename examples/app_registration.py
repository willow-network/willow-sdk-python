"""
Willow Python SDK - Subgrove Registration Example

This example demonstrates how to:
1. Register a subgrove
2. Define schemas with indexes
3. Create subgroves for data organization
4. Manage permissions

Prerequisites:
- pip install willow-sdk
- Run a local Willow node
- Have WILL tokens for funding
"""

import asyncio
from willow import (
    WillowClient,
    generate_did,
    WillowError,

    RegisterSubgroveRequest,
    SchemaDefinition,
    FieldType,
    IndexDefinition,
)


async def main():
    print("Willow Subgrove Registration Demo")
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

        # 1. Register a Subgrove
        print("\n1. Register Subgrove")
        print("-" * 40)



        try:

        # 2. Define a Schema with Indexes
        print("\n2. Define Schema with Indexes")
        print("-" * 40)

        # Product catalog schema with various index types
        product_schema = SchemaDefinition(
            version=1,
            fields={
                "sku": FieldType(type="string", indexed=True, required=True),
                "name": FieldType(type="string", indexed=True, required=True),
                "description": FieldType(type="string", indexed=True),
                "category": FieldType(type="string", indexed=True, required=True),
                "price": FieldType(type="number", indexed=True, required=True),
                "stock": FieldType(type="number", indexed=True),
                "tags": FieldType(type="array"),
                "specifications": FieldType(type="object"),
            },
            indexes=[
                # Unique constraint
                IndexDefinition(
                    name="unique_sku",
                    fields=["sku"],
                    unique=True,
                    type="unique"
                ),
                # Hash index for category lookups
                IndexDefinition(
                    name="by_category",
                    fields=["category"],
                    unique=False,
                    type="hash"
                ),
                # Range index for price queries
                IndexDefinition(
                    name="by_price",
                    fields=["price"],
                    unique=False,
                    type="range"
                ),
                # Fulltext search
                IndexDefinition(
                    name="product_search",
                    fields=["name", "description"],
                    unique=False,
                    type="fulltext"
                ),
                # Compound index
                IndexDefinition(
                    name="category_price",
                    fields=["category", "price"],
                    unique=False,
                    type="compound"
                ),
            ]
        )

        print("Schema defined with indexes:")
        print("  - unique_sku: Unique constraint on SKU")
        print("  - by_category: Hash index for category")
        print("  - by_price: Range index for price queries")
        print("  - product_search: Fulltext on name/description")
        print("  - category_price: Compound index")

        # 3. Create a Subgrove
        print("\n3. Create Subgrove")
        print("-" * 40)

        try:
            subgrove_request = RegisterSubgroveRequest(
                subgrove_id="products",

                name="Product Catalog",
                description="All product data",
                schema=product_schema.model_dump(),
                owner_did=did_info["did"],
                writers=[did_info["did"]],
                readers=[],  # Empty = public read
                reward_rate=1000,  # Indexer reward rate
            )
            await client.registration.register_subgrove(subgrove_request)
            print("Created subgrove: products")
        except WillowError as e:
            print(f"Error (may already exist): {e}")

        # 4. List Subgroves
        print("\n4. List Registered Subgroves")
        print("-" * 40)

        try:
            subgroves = await client.registration.list_subgroves()
            print(f"Found {len(subgroves)} subgroves:")
            for sg in subgroves[:5]:
                print(f"  - {sg.subgrove_id}: {sg.name}")
        except WillowError as e:
            print(f"Error: {e}")

        # 5. Get Subgrove Details
        print("\n5. Get Subgrove Details")
        print("-" * 40)

        try:
subgrove = await client.registration.get_subgrove("products")
            print(f"Subgrove: {subgrove.subgrove_id}")
            print(f"Name: {subgrove.name}")
            print(f"Owner: {subgrove.owner_did}")
        except WillowError as e:
            print(f"Error: {e}")

        # 6. List Subgroves
        print("\n6. List Subgroves")
        print("-" * 40)

        try:
subgroves = await client.registration.list_subgroves()
            print(f"Found {len(subgroves)} subgroves:")
            for sg in subgroves:
                print(f"  - {sg.subgrove_id}: {sg.name}")
        except WillowError as e:
            print(f"Error: {e}")

        # 7. Get Subgrove Details
        print("\n7. Get Subgrove Details")
        print("-" * 40)

        try:
subgrove = await client.registration.get_subgrove("products")
            print(f"Subgrove: {subgrove.subgrove_id}")
            print(f"Reward Rate: {subgrove.reward_rate}")
        except WillowError as e:
            print(f"Error: {e}")

        # 8. Check Permissions
        print("\n8. Check Permissions")
        print("-" * 40)

        try:
            permissions = await client.registration.get_permissions(

                subgrove_id="products",
                did=did_info["did"]
            )
            print(f"Can read: {permissions.can_read}")
            print(f"Can write: {permissions.can_write}")
            print(f"Is owner: {permissions.is_owner}")
        except WillowError as e:
            print(f"Error: {e}")

    print("\n" + "=" * 50)
    print("Registration Complete!")
    print("\nData Organization:")
    print("  Subgrove (products)")
    print("    -> Items (with schema validation)")
    print("    -> Indexes (for fast queries)")



if __name__ == "__main__":
    asyncio.run(main())
