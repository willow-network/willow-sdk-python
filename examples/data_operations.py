"""
Willow Python SDK - Data Operations Example

This example demonstrates comprehensive data operations:
1. Store single items
2. Batch store multiple items
3. Get single item
4. Query with filters
5. Update items
6. Delete items

All operations include automatic proof verification by default.

Prerequisites:
- pip install willow-sdk
- Run a local Willow node
- Register and fund a subgrove
"""

import asyncio
from willow import (
    WillowClient,
    generate_did,
    WillowError,
)


async def main():
    print("Willow Data Operations Demo")
    print("=" * 50)

    # Setup
    did_info = generate_did()

    async with WillowClient("http://localhost:3031") as client:
        # Authenticate
        await client.register_did(did_info["did_document"])
        await client.authenticate(
            did=did_info["did"],
            private_key_hex=did_info["private_key"],
            public_key_id=did_info["public_key_id"]
        )


        collection = "products"

        # 1. Store single item
        print("\n1. Store Single Item")
        print("-" * 40)

        try:
            await client.data.store(

                collection=collection,
                data={
                    "id": "prod-001",
                    "name": "Laptop Pro",
                    "category": "electronics",
                    "price": 1299.99,
                    "stock": 50
                }
            )
            print("Stored product: prod-001")
        except WillowError as e:
            print(f"Error: {e}")

        # 2. Batch store multiple items
        print("\n2. Batch Store Multiple Items")
        print("-" * 40)

        products = [
            {
                "key": "prod-002",
                "value": {
                    "id": "prod-002",
                    "name": "Wireless Mouse",
                    "category": "electronics",
                    "price": 49.99,
                    "stock": 200
                }
            },
            {
                "key": "prod-003",
                "value": {
                    "id": "prod-003",
                    "name": "USB-C Cable",
                    "category": "accessories",
                    "price": 19.99,
                    "stock": 500
                }
            },
            {
                "key": "prod-004",
                "value": {
                    "id": "prod-004",
                    "name": "Monitor 27\"",
                    "category": "electronics",
                    "price": 399.99,
                    "stock": 30
                }
            }
        ]

        try:
await client.data.batch_store(collection, products)
            print(f"Batch stored {len(products)} products")
        except WillowError as e:
            print(f"Error: {e}")

        # 3. Get single item (with proof verification)
        print("\n3. Get Single Item")
        print("-" * 40)

        try:
item = await client.data.get(collection, "prod-001")
            print(f"Retrieved: {item}")
            print("Proof verified automatically")
        except WillowError as e:
            print(f"Error: {e}")

        # 4. Get unverified (faster, no proof check)
        print("\n4. Get Unverified (Performance Mode)")
        print("-" * 40)

        try:
item = await client.data.get_unverified(collection, "prod-001")
            print(f"Retrieved (unverified): {item}")
        except WillowError as e:
            print(f"Error: {e}")

        # 5. Query with filters
        print("\n5. Query with Filters")
        print("-" * 40)

        try:
            # Filter by category
            result = await client.data.query(

                collection=collection,
                query={
                    "filters": {
                        "category": "electronics"
                    }
                }
            )
            print(f"Electronics products: {len(result.documents)}")
            for doc in result.documents:
                print(f"  - {doc.get('name', 'Unknown')}")
        except WillowError as e:
            print(f"Error: {e}")

        # 6. Query with range filter
        print("\n6. Query with Range Filter")
        print("-" * 40)

        try:
            result = await client.data.query(

                collection=collection,
                query={
                    "filters": {
                        "price": {
                            "$gte": 50,
                            "$lte": 500
                        }
                    }
                }
            )
            print(f"Products $50-$500: {len(result.documents)}")
            for doc in result.documents:
                print(f"  - {doc.get('name', 'Unknown')}: ${doc.get('price', 0)}")
        except WillowError as e:
            print(f"Error: {e}")

        # 7. Query with sorting and pagination
        print("\n7. Query with Sorting and Pagination")
        print("-" * 40)

        try:
            result = await client.data.query(

                collection=collection,
                query={
                    "sort": {
                        "field": "price",
                        "order": "desc"
                    },
                    "limit": 2,
                    "offset": 0
                }
            )
            print("Top 2 by price (descending):")
            for doc in result.documents:
                print(f"  - {doc.get('name', 'Unknown')}: ${doc.get('price', 0)}")
        except WillowError as e:
            print(f"Error: {e}")

        # 8. Update item
        print("\n8. Update Item")
        print("-" * 40)

        try:
            await client.data.update(

                collection=collection,
                key="prod-001",
                data={
                    "id": "prod-001",
                    "name": "Laptop Pro",
                    "category": "electronics",
                    "price": 1199.99,  # Price reduced!
                    "stock": 45,
                    "on_sale": True
                }
            )
            print("Updated prod-001 (price reduced, on_sale flag added)")
        except WillowError as e:
            print(f"Error: {e}")

        # 9. Delete item
        print("\n9. Delete Item")
        print("-" * 40)

        try:
await client.data.delete(collection, "prod-004")
            print("Deleted prod-004")
        except WillowError as e:
            print(f"Error: {e}")

    print("\n" + "=" * 50)
    print("Data Operations Complete!")


if __name__ == "__main__":
    asyncio.run(main())
