"""
Willow Python SDK - Subgrove Registration Example

Demonstrates:
1. Define a schema
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
)


async def main():
    print("Willow Subgrove Registration Demo")
    print("=" * 50)

    did_info = generate_did()

    async with WillowClient("http://localhost:3031") as client:
        # Auth: the identity signs the DID's registration (pre-fund the DID
        # with the registration fee first) and every later transaction.
        client.set_identity(
            did_info["did"],
            did_info["private_key"],
            did_info["public_key_id"],
        )
        # A write returns once CheckTx accepts it: wait for the registration
        # to land before the DID signs anything else.
        await client.wait_until_landed(await client.register_did(did_info["did_document"]))

        # 1. Define a schema. Each field has a type; required fields must be
        # present in every item. The node supports no schema indexes: a schema
        # with indexes, or a field flagged indexed, is refused before signing.
        print("\n1. Define Schema")
        print("-" * 40)
        product_schema = SchemaDefinition(
            version=1,
            fields={
                "sku": FieldType(type="string", required=True),
                "name": FieldType(type="string", required=True),
                "description": FieldType(type="string"),
                "category": FieldType(type="string", required=True),
                "price": FieldType(type="number", required=True),
                "stock": FieldType(type="number"),
                "tags": FieldType(type="array"),
                "specifications": FieldType(type="object"),
            },
        )
        print("Schema defined: sku, name, category, and price required")

        # 2. Register the subgrove. Its ID is 1 to 64 ASCII letters, digits,
        # '-', or '_', starting with a letter or digit.
        print("\n2. Register Subgrove")
        print("-" * 40)
        try:
            subgrove_request = RegisterSubgroveRequest(
                dataset_id="products",
                name="Product Catalog",
                schema=product_schema,
                owner_did=did_info["did"],
                writers=[did_info["did"]],
                readers=[],
            )
            registration = await client.registration.register_subgrove(
                subgrove_request.model_dump(by_alias=True)
            )
            # Wait for it to land before reading it or storing into it.
            await client.wait_until_landed(registration)
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


if __name__ == "__main__":
    asyncio.run(main())
