"""
Indexing tests for Willow Python SDK

These tests require a running three-node network with funded DID.
Run: ./scripts/start_network.sh
"""

import pytest
import asyncio
import os
from pathlib import Path
from typing import Dict, List, Any

from willow import (
    WillowClient,
    FieldType,
    IndexDefinition,
    SchemaDefinition,
    RegisterDatasetRequest,
    QueryRequest,
    QuerySearch,
    QuerySort,
)


# Constants for the test
PRIVATE_KEY_HEX = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
PUBLIC_KEY_HEX = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
PUBLIC_KEY_ID = "#key1"


# Helper to get funded DID
def get_funded_did() -> str:
    """Read the funded DID from the file created by the script."""
    did_path = Path(__file__).parent.parent.parent.parent / "devnet" / "test_owner_did.txt"
    try:
        return did_path.read_text().strip()
    except FileNotFoundError:
        raise Exception("Test DID file not found - ensure network is running with funding")


# Test fixtures
@pytest.fixture
async def client1():
    """Client for node 1."""
    client = WillowClient(api_url="http://localhost:3031")
    yield client
    await client.close()


@pytest.fixture
async def client2():
    """Client for node 2."""
    client = WillowClient(api_url="http://localhost:3032")
    yield client
    await client.close()


@pytest.fixture
async def client3():
    """Client for node 3."""
    client = WillowClient(api_url="http://localhost:3033")
    yield client
    await client.close()


@pytest.fixture
def funded_did():
    """Get the funded DID."""
    return get_funded_did()


@pytest.fixture
def dataset_prefix():
    """App ID for tests."""
    return "blog_posts"


class TestSchemaAndIndexRegistration:
    """Test schema and index registration."""
    
    @pytest.mark.asyncio
    async def test_register_dataset_with_indexes(self, client1, funded_did, dataset_prefix):
        """Test registering a dataset with multiple index types."""
        # Authenticate
        client1.set_identity(funded_did, PRIVATE_KEY_HEX, PUBLIC_KEY_ID)
        
        # Define schema with various field types
        schema = SchemaDefinition(
            version=1,
            fields={
                "title": FieldType(type="string", indexed=True, required=True),
                "content": FieldType(type="string", indexed=True, required=True),
                "author": FieldType(type="string", indexed=True, required=True),
                "tags": FieldType(type="array", indexed=True),
                "timestamp": FieldType(type="number", indexed=True, required=True),
                "views": FieldType(type="number", indexed=True),
                "metadata": FieldType(type="object"),
            },
            indexes=[
                IndexDefinition(
                    name="by_author",
                    fields=["author"],
                    unique=False,
                    type="hash"
                ),
                IndexDefinition(
                    name="by_timestamp",
                    fields=["timestamp"],
                    unique=False,
                    type="range"
                ),
                IndexDefinition(
                    name="unique_title",
                    fields=["title"],
                    unique=True,
                    type="unique"
                ),
                IndexDefinition(
                    name="content_search",
                    fields=["content"],
                    unique=False,
                    type="fulltext"
                ),
            ]
        )
        
        # Register dataset
        dataset_request = {
            "dataset_id": "blog_posts",

            "name": "Blog Posts with Indexes",
            "dataset_path": [],
            "schema": schema.model_dump(),
            "owner_did": funded_did,
            "writers": [],
            "readers": [],
        }
        
        registration = await client1.registration.register_dataset(dataset_request)
        assert registration["dataset_id"] == "blog_posts"
        assert len(registration["schema"]["indexes"]) == 4
        
        # Wait for propagation
        await asyncio.sleep(3)


class TestIndexedDataStorage:
    """Test storing and retrieving indexed data."""
    
    @pytest.mark.asyncio
    async def test_store_indexed_documents(self, client1, client2, funded_did, dataset_prefix):
        """Test storing documents that will be indexed."""
        # Authenticate both clients
        client1.set_identity(funded_did, PRIVATE_KEY_HEX, PUBLIC_KEY_ID)
        client2.set_identity(funded_did, PRIVATE_KEY_HEX, PUBLIC_KEY_ID)
        
        # Test data
        test_posts = [
            {
                "key": "post_1",
                "value": {
                    "title": "Introduction to Python SDK",
                    "content": "Learn how to use the Willow Python SDK for decentralized indexing",
                    "author": "alice",
                    "tags": ["python", "sdk", "tutorial"],
                    "timestamp": 1000,
                    "views": 150,
                    "metadata": {"difficulty": "beginner"},
                }
            },
            {
                "key": "post_2",
                "value": {
                    "title": "Advanced Indexing Patterns",
                    "content": "Explore advanced indexing patterns including fulltext search and compound indexes",
                    "author": "alice",
                    "tags": ["indexing", "advanced", "patterns"],
                    "timestamp": 2000,
                    "views": 300,
                    "metadata": {"difficulty": "advanced"},
                }
            },
            {
                "key": "post_3",
                "value": {
                    "title": "Building DApps with Willow",
                    "content": "How to build decentralized applications using Willow indexing infrastructure",
                    "author": "bob",
                    "tags": ["dapp", "blockchain", "tutorial"],
                    "timestamp": 1500,
                    "views": 225,
                    "metadata": {"difficulty": "intermediate"},
                }
            },
        ]
        
        # Store documents
        await client1.data.batch_store( "blog_posts", test_posts)
        
        # Wait for indexing
        await asyncio.sleep(5)
        
        # Verify data was stored
        retrieved = await client2.data.get( "blog_posts", "post_1")
        assert retrieved["title"] == "Introduction to Python SDK"
        assert retrieved["author"] == "alice"


class TestQueryOperations:
    """Test various query operations."""
    
    @pytest.mark.asyncio
    async def test_query_by_indexed_field(self, client2, funded_did, dataset_prefix):
        """Test querying by indexed field (author)."""
        client2.set_identity(funded_did, PRIVATE_KEY_HEX, PUBLIC_KEY_ID)
        
        query = {
            "filters": {
                "author": "alice"
            }
        }
        
        results = await client2.data.query( "blog_posts", query)
        assert len(results.documents) == 2
        assert all(doc["author"] == "alice" for doc in results.documents)
    
    @pytest.mark.asyncio
    async def test_range_queries(self, client2, funded_did, dataset_prefix):
        """Test range queries on numeric fields."""
        client2.set_identity(funded_did, PRIVATE_KEY_HEX, PUBLIC_KEY_ID)
        
        query = {
            "filters": {
                "timestamp": {
                    "$gte": 1000,
                    "$lte": 1500
                }
            }
        }
        
        results = await client2.data.query( "blog_posts", query)
        assert len(results.documents) == 2
        assert all(1000 <= doc["timestamp"] <= 1500 for doc in results.documents)
    
    @pytest.mark.asyncio
    async def test_fulltext_search(self, client2, funded_did, dataset_prefix):
        """Test fulltext search functionality."""
        client2.set_identity(funded_did, PRIVATE_KEY_HEX, PUBLIC_KEY_ID)
        
        query = {
            "search": {
                "field": "content",
                "query": "indexing"
            }
        }
        
        results = await client2.data.query( "blog_posts", query)
        assert len(results.documents) >= 2
        assert any("indexing" in doc["content"].lower() for doc in results.documents)
    
    @pytest.mark.asyncio
    async def test_sorting(self, client2, funded_did, dataset_prefix):
        """Test sorting query results."""
        client2.set_identity(funded_did, PRIVATE_KEY_HEX, PUBLIC_KEY_ID)
        
        query = {
            "sort": {
                "field": "views",
                "order": "desc"
            }
        }
        
        results = await client2.data.query( "blog_posts", query)
        assert len(results.documents) == 3
        
        # Verify descending order
        for i in range(1, len(results.documents)):
            assert results.documents[i-1]["views"] >= results.documents[i]["views"]
    
    @pytest.mark.asyncio
    async def test_pagination(self, client2, funded_did, dataset_prefix):
        """Test pagination with limit and offset."""
        client2.set_identity(funded_did, PRIVATE_KEY_HEX, PUBLIC_KEY_ID)
        
        # First page
        page1_query = {
            "sort": {"field": "timestamp", "order": "asc"},
            "limit": 2,
            "offset": 0
        }
        
        page1 = await client2.data.query( "blog_posts", page1_query)
        assert len(page1.documents) == 2
        assert page1.limit == 2
        assert page1.offset == 0
        
        # Second page
        page2_query = {
            "sort": {"field": "timestamp", "order": "asc"},
            "limit": 2,
            "offset": 2
        }
        
        page2 = await client2.data.query( "blog_posts", page2_query)
        assert len(page2.documents) <= 2
        assert page2.offset == 2
    
    @pytest.mark.asyncio
    async def test_compound_queries(self, client2, funded_did, dataset_prefix):
        """Test compound queries with multiple conditions."""
        client2.set_identity(funded_did, PRIVATE_KEY_HEX, PUBLIC_KEY_ID)
        
        query = {
            "filters": {
                "author": "alice",
                "views": {"$gte": 200}
            },
            "sort": {
                "field": "timestamp",
                "order": "desc"
            }
        }
        
        results = await client2.data.query( "blog_posts", query)
        assert len(results.documents) == 1
        assert results.documents[0]["author"] == "alice"
        assert results.documents[0]["views"] >= 200


class TestCrossNodeConsistency:
    """Test consistency across multiple nodes."""
    
    @pytest.mark.asyncio
    async def test_query_consistency_across_nodes(self, client1, client2, client3, funded_did, dataset_prefix):
        """Test that all nodes return consistent query results."""
        # Authenticate all clients
        client1.set_identity(funded_did, PRIVATE_KEY_HEX, PUBLIC_KEY_ID)
        client2.set_identity(funded_did, PRIVATE_KEY_HEX, PUBLIC_KEY_ID)
        client3.set_identity(funded_did, PRIVATE_KEY_HEX, PUBLIC_KEY_ID)
        
        query = {
            "sort": {"field": "timestamp", "order": "asc"}
        }
        
        # Query from all nodes
        results = await asyncio.gather(
            client1.data.query( "blog_posts", query),
            client2.data.query( "blog_posts", query),
            client3.data.query( "blog_posts", query)
        )
        
        results1, results2, results3 = results
        
        # All nodes should return the same number of documents
        assert len(results1.documents) == len(results2.documents) == len(results3.documents)
        
        # Documents should be in the same order
        for i in range(len(results1.documents)):
            assert results1.documents[i]["title"] == results2.documents[i]["title"]
            assert results2.documents[i]["title"] == results3.documents[i]["title"]


class TestUniqueConstraints:
    """Test unique constraint enforcement."""
    
    @pytest.mark.asyncio
    async def test_unique_constraint_enforcement(self, client1, funded_did, dataset_prefix):
        """Test that unique constraints are enforced."""
        client1.set_identity(funded_did, PRIVATE_KEY_HEX, PUBLIC_KEY_ID)
        
        duplicate_post = {
            "title": "Introduction to Python SDK",  # Duplicate title
            "content": "This should fail due to unique constraint",
            "author": "charlie",
            "timestamp": 3000,
            "views": 50,
        }
        
        # This should raise an exception
        with pytest.raises(Exception):
            await client1.data.store( "blog_posts", {"post_duplicate": duplicate_post})


class TestPerformance:
    """Performance tests for indexing operations."""
    
    @pytest.mark.asyncio
    async def test_bulk_indexing_performance(self, client1, funded_did, dataset_prefix):
        """Test bulk indexing performance."""
        client1.set_identity(funded_did, PRIVATE_KEY_HEX, PUBLIC_KEY_ID)
        
        # Create performance test dataset
        perf_schema = SchemaDefinition(
            version=1,
            fields={
                "id": FieldType(type="string", indexed=True, required=True),
                "category": FieldType(type="string", indexed=True, required=True),
                "value": FieldType(type="number", indexed=True, required=True),
                "description": FieldType(type="string"),
            },
            indexes=[
                IndexDefinition(name="by_category", fields=["category"], unique=False, type="hash"),
                IndexDefinition(name="by_value", fields=["value"], unique=False, type="range"),
            ]
        )
        
        perf_dataset = {
            "dataset_id": "perf_test",

            "name": "Performance Test Dataset",
            "dataset_path": [],
            "schema": perf_schema.model_dump(),
            "owner_did": funded_did,
            "writers": [],
            "readers": [],
        }
        
        await client1.registration.register_dataset(perf_dataset)
        await asyncio.sleep(3)
        
        # Generate test data
        categories = ["electronics", "books", "clothing", "food", "toys"]
        test_data = [
            {
                "key": f"item_{i}",
                "value": {
                    "id": f"item_{i}",
                    "category": categories[i % len(categories)],
                    "value": (i * 10) % 1000,
                    "description": f"Test item {i}",
                }
            }
            for i in range(50)
        ]
        
        # Measure bulk insert time
        import time
        start_time = time.time()
        await client1.data.batch_store( "perf_test", test_data)
        await asyncio.sleep(5)  # Wait for indexing
        insert_time = (time.time() - start_time) * 1000  # Convert to ms
        
        print(f"Inserted 50 documents in {insert_time:.0f}ms")
        assert insert_time < 10000  # Should complete within 10 seconds
        
        # Test query performance
        query_start = time.time()
        category_results = await client1.data.query( "perf_test", {
            "filters": {"category": "electronics"}
        })
        category_query_time = (time.time() - query_start) * 1000
        
        print(f"Category query returned {len(category_results.documents)} results in {category_query_time:.0f}ms")
        assert category_query_time < 1000  # Should complete within 1 second
        
        # Range query performance
        range_start = time.time()
        range_results = await client1.data.query( "perf_test", {
            "filters": {
                "value": {"$gte": 200, "$lte": 500}
            }
        })
        range_query_time = (time.time() - range_start) * 1000
        
        print(f"Range query returned {len(range_results.documents)} results in {range_query_time:.0f}ms")
        assert range_query_time < 1000


# Run all tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])