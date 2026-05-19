"""
Willow Python SDK - Subgrove Registration Example

Demonstrates:
1. Define a schema with multiple index types
2. Register a subgrove
3. List subgroves
4. Get a subgrove
5. Check DID permissions

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
        # Auth
        await client.register_did(did_info["did_document"])
        client.set_identity(
            did_info["did"],
            did_info["private_key"],
            did_info["public_key_id"],
        )

        # 1. Define a schema with indexes
        print("\n1. Define Schema with Indexes")
        print("-" * 40)
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
                IndexDefinition(name="unique_sku", fields=["sku"], unique=True, type="unique"),
                IndexDefinition(name="by_category", fields=["category"], unique=False, type="hash"),
                IndexDefinition(name="by_price", fields=["price"], unique=False, type="range"),
                IndexDefinition(
                    name="product_search",
                    fields=["name", "description"],
                    unique=False,
                    type="fulltext",
                ),
                IndexDefinition(
                    name="category_price",
                    fields=["category", "price"],
                    unique=False,
                    type="compound",
                ),
            ],
        )
        print("Schema defined with indexes:")
        print("  - unique_sku: Unique constraint on SKU")
        print("  - by_category: Hash index for category")
        print("  - by_price: Range index for price queries")
        print("  - product_search: Fulltext on name/description")
        print("  - category_price: Compound index")

        # 2. Register the subgrove
        print("\n2. Register Subgrove")
        print("-" * 40)
        try:
            subgrove_request = RegisterSubgroveRequest(
                dataset_id="products",
                name="Product Catalog",
                dataset_path=["collections"],
                schema=product_schema,
                owner_did=did_info["did"],
                writers=[did_info["did"]],
                readers=[],
            )
            await client.registration.register_subgrove(subgrove_request.model_dump(by_alias=True))
            print("Created subgrove: products")
        except WillowError as e:
            print(f"Error (may already exist): {e}")

        # 3. List subgroves
        print("\n3. List Registered Subgroves")
        print("-" * 40)
        try:
            subgroves = await client.registration.list_subgroves()
            print(f"Found {len(subgroves)} subgroves:")
            for sg in subgroves[:5]:
                print(f"  - {sg.subgrove_id}: {sg.name}")
        except WillowError as e:
            print(f"Error: {e}")

        # 4. Get a subgrove
        print("\n4. Get Subgrove Details")
        print("-" * 40)
        try:
            subgrove = await client.registration.get_subgrove("products")
            print(f"Subgrove: {subgrove.subgrove_id}")
            print(f"Name: {subgrove.name}")
            print(f"Owner: {subgrove.owner_did}")
            print(f"Writers: {len(subgrove.writers)}, Readers: {len(subgrove.readers)}")
        except WillowError as e:
            print(f"Error: {e}")

        # 5. Check DID permissions
        print("\n5. Check Permissions")
        print("-" * 40)
        try:
            permissions = await client.registration.get_permissions(did_info["did"])
            print(f"Owned: {len(permissions.owned_subgroves)} ({permissions.owned_subgroves[:3]})")
            print(f"Admin: {len(permissions.admin_subgroves)}")
            print(f"Write access: {len(permissions.write_access)}")
            print(f"Read access: {len(permissions.read_access)}")
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
