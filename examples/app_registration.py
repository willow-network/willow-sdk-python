"""
Willow Python SDK - App and Subgrove Registration Example

This example demonstrates how to:
1. Register an application
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
    RegisterAppRequest,
    RegisterSubgroveRequest,
    SchemaDefinition,
    FieldType,
    IndexDefinition,
)


async def main():
    print("Willow App Registration Demo")
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

        # 1. Register an Application
        print("\n1. Register Application")
        print("-" * 40)

        app_id = "my-ecommerce-app"

        try:
            app_request = RegisterAppRequest(
                app_id=app_id,
                name="My E-commerce App",
                description="A demo e-commerce application",
                owner_did=did_info["did"],
                metadata={"version": "1.0.0"}
            )
            await client.registration.register_app(app_request)
            print(f"Registered app: {app_id}")
        except WillowError as e:
            print(f"Error (may already exist): {e}")

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
                app_id=app_id,
                name="Product Catalog",
                description="All product data",
                schema=product_schema.model_dump(),
                owner_did=did_info["did"],
                writers=[did_info["did"]],
                readers=[],  # Empty = public read
                reward_rate=1000,  # Indexer reward rate
            )
            await client.registration.register_subgrove(subgrove_request)
            print(f"Created subgrove: {app_id}/products")
        except WillowError as e:
            print(f"Error (may already exist): {e}")

        # 4. List Apps
        print("\n4. List Registered Apps")
        print("-" * 40)

        try:
            apps = await client.registration.list_apps()
            print(f"Found {len(apps)} apps:")
            for app in apps[:5]:
                print(f"  - {app.app_id}: {app.name}")
        except WillowError as e:
            print(f"Error: {e}")

        # 5. Get App Details
        print("\n5. Get App Details")
        print("-" * 40)

        try:
            app = await client.registration.get_app(app_id)
            print(f"App ID: {app.app_id}")
            print(f"Name: {app.name}")
            print(f"Owner: {app.owner_did}")
        except WillowError as e:
            print(f"Error: {e}")

        # 6. List Subgroves
        print("\n6. List Subgroves")
        print("-" * 40)

        try:
            subgroves = await client.registration.list_subgroves(app_id)
            print(f"Found {len(subgroves)} subgroves:")
            for sg in subgroves:
                print(f"  - {sg.subgrove_id}: {sg.name}")
        except WillowError as e:
            print(f"Error: {e}")

        # 7. Get Subgrove Details
        print("\n7. Get Subgrove Details")
        print("-" * 40)

        try:
            subgrove = await client.registration.get_subgrove(app_id, "products")
            print(f"Subgrove: {subgrove.subgrove_id}")
            print(f"Reward Rate: {subgrove.reward_rate}")
        except WillowError as e:
            print(f"Error: {e}")

        # 8. Check Permissions
        print("\n8. Check Permissions")
        print("-" * 40)

        try:
            permissions = await client.registration.get_permissions(
                app_id=app_id,
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
    print("  App (my-ecommerce-app)")
    print("    -> Subgrove (products)")
    print("         -> Items (with schema validation)")
    print("         -> Indexes (for fast queries)")


if __name__ == "__main__":
    asyncio.run(main())
