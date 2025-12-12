"""
Willow Python SDK - Proof Verification Example

This example demonstrates the trustless proof verification capabilities:
1. Automatic verification (default behavior)
2. Manual verification with expected root hash
3. Quick root hash extraction
4. Unverified operations for performance

All verification is done locally using pure Python - no server trust required.

Prerequisites:
- pip install willow-sdk
- Run a local Willow node
"""

import asyncio
from willow import (
    WillowClient,
    GroveDBProofVerifier,
    ProofVerificationOptions,
    verify_proof_quick,
    verify_proof_with_expected_root,
    ProofVerificationError,
    grovedb,
)


async def main():
    print("Willow Proof Verification Demo")
    print("=" * 50)

    # Example 1: Automatic verification (default)
    print("\n1. Automatic Proof Verification")
    print("-" * 40)

    async with WillowClient("http://localhost:3031") as client:
        # All data operations verify proofs by default
        try:
            result = await client.data.query(
                app_id="demo-app",
                collection="items",
                query={"filters": {"status": "active"}}
            )
            print(f"Query returned {len(result.documents)} results")
            print("All results are cryptographically verified!")
        except ProofVerificationError as e:
            print(f"Verification failed: {e}")
        except Exception as e:
            print(f"Query error: {e}")

    # Example 2: Manual verification with GroveDBProofVerifier
    print("\n2. Manual Proof Verification")
    print("-" * 40)

    # Create a verifier with specific options
    verifier = GroveDBProofVerifier(
        ProofVerificationOptions(
            deserialize_elements=True,
            limit=100
        )
    )

    # Verify a proof (hex-encoded)
    sample_proof = "00" + "ff" * 32  # Invalid proof for demo
    result = await verifier.verify_query_proof(
        proof_hex=sample_proof,
        documents=[{"key": "test", "value": {"data": "example"}}]
    )
    print(f"Valid: {result.valid}")
    print(f"Error: {result.error}")

    # Example 3: Verify against expected root hash
    print("\n3. Verify Against Expected Root Hash")
    print("-" * 40)

    expected_root = "a" * 64  # 32-byte hash as hex
    verifier_with_root = GroveDBProofVerifier(
        ProofVerificationOptions(expected_root_hash=expected_root)
    )

    result = await verifier_with_root.verify_query_proof(
        proof_hex=sample_proof,
        documents=[]
    )
    print(f"Matches expected root: {result.valid}")

    # Example 4: Quick root hash extraction
    print("\n4. Quick Root Hash Extraction")
    print("-" * 40)

    try:
        # This parses the proof and computes the root hash
        root_hash = verify_proof_quick(sample_proof)
        print(f"Extracted root hash: {root_hash[:16]}...")
    except ProofVerificationError as e:
        print(f"Could not extract root hash: {e}")

    # Example 5: Verify proof matches root
    print("\n5. Verify Proof Matches Root")
    print("-" * 40)

    try:
        matches = verify_proof_with_expected_root(sample_proof, expected_root)
        print(f"Proof matches root: {matches}")
    except ProofVerificationError as e:
        print(f"Verification failed: {e}")

    # Example 6: Unverified operations (performance mode)
    print("\n6. Unverified Operations (Performance Mode)")
    print("-" * 40)

    async with WillowClient("http://localhost:3031") as client:
        try:
            # Skip verification for maximum performance
            result = await client.data.query_unverified(
                app_id="demo-app",
                collection="items",
                query={"filters": {"status": "active"}}
            )
            print(f"Unverified query returned {len(result.documents)} results")
            print("WARNING: Results not cryptographically verified!")
        except Exception as e:
            print(f"Query error: {e}")

    # Example 7: Low-level grovedb module access
    print("\n7. Low-Level GroveDB Access")
    print("-" * 40)

    # Direct access to GroveDB functions
    print(f"Hash length: {grovedb.HASH_LENGTH} bytes")
    print(f"Null hash: {grovedb.hash_to_hex(grovedb.NULL_HASH)[:16]}...")

    # BLAKE3 hashing
    test_data = b"Hello, Willow!"
    hash_result = grovedb.blake3_hash(test_data)
    print(f"BLAKE3 hash: {grovedb.hash_to_hex(hash_result)[:16]}...")

    print("\n" + "=" * 50)
    print("Key Takeaways:")
    print("- All verification is done locally (trustless)")
    print("- Proofs use GroveDB Merkle tree structure")
    print("- Root hash can be compared against consensus")
    print("- Use unverified operations only when trust is acceptable")


if __name__ == "__main__":
    asyncio.run(main())
