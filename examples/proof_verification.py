"""
Willow Python SDK - Proof Verification Example

Demonstrates trustless proof verification:
1. Automatic verification (default behaviour)
2. Manual verification with a GroveDBProofVerifier instance
3. Verify against a pinned expected root hash
4. Quick root-hash extraction
5. Unverified operations (performance mode)
6. Low-level grovedb module access

All verification is done locally - no server trust required.

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


SUBGROVE = "items"


async def main():
    print("Willow Proof Verification Demo")
    print("=" * 50)

    # 1. Automatic verification (default on query/get)
    print("\n1. Automatic Proof Verification")
    print("-" * 40)
    async with WillowClient("http://localhost:3031") as client:
        try:
            result = await client.data.query(
                SUBGROVE,
                {"filters": {"status": "active"}},
            )
            print(f"Query returned {len(result.documents)} results")
            print("All results are cryptographically verified.")
        except ProofVerificationError as e:
            print(f"Verification failed: {e}")
        except Exception as e:
            print(f"Query error: {e}")

    # 2. Manual verification
    print("\n2. Manual Proof Verification")
    print("-" * 40)
    verifier = GroveDBProofVerifier(
        ProofVerificationOptions(
            deserialize_elements=True,
            limit=100,
        )
    )
    sample_proof = "00" + "ff" * 32  # Intentionally invalid for demo.
    result = await verifier.verify_query_proof(
        proof_hex=sample_proof,
        documents=[{"key": "test", "value": {"data": "example"}}],
    )
    print(f"Valid: {result.valid}")
    print(f"Error: {result.error}")

    # 3. Pin a verifier to an expected root hash
    print("\n3. Verify Against Expected Root Hash")
    print("-" * 40)
    expected_root = "a" * 64
    pinned_verifier = GroveDBProofVerifier(
        ProofVerificationOptions(expected_root_hash=expected_root)
    )
    result = await pinned_verifier.verify_query_proof(
        proof_hex=sample_proof,
        documents=[],
    )
    print(f"Matches expected root: {result.valid}")

    # 4. Quick root-hash extraction
    print("\n4. Quick Root Hash Extraction")
    print("-" * 40)
    try:
        root_hash = verify_proof_quick(sample_proof)
        print(f"Extracted root hash: {root_hash[:16]}...")
    except ProofVerificationError as e:
        print(f"Could not extract root hash: {e}")

    # 5. Proof-vs-expected-root one-shot
    print("\n5. Verify Proof Matches Expected Root")
    print("-" * 40)
    try:
        matches = verify_proof_with_expected_root(sample_proof, expected_root)
        print(f"Proof matches expected root: {matches}")
    except ProofVerificationError as e:
        print(f"Verification failed: {e}")

    # 6. Unverified operations (performance mode)
    print("\n6. Unverified Operations (Performance Mode)")
    print("-" * 40)
    async with WillowClient("http://localhost:3031") as client:
        try:
            result = await client.data.query_unverified(
                SUBGROVE,
                {"filters": {"status": "active"}},
            )
            print(f"Unverified query returned {len(result.documents)} results")
            print("WARNING: results not cryptographically verified.")
        except Exception as e:
            print(f"Query error: {e}")

    # 7. Low-level grovedb module access
    print("\n7. Low-Level GroveDB Access")
    print("-" * 40)
    print(f"Hash length: {grovedb.HASH_LENGTH} bytes")
    print(f"Null hash: {grovedb.hash_to_hex(grovedb.NULL_HASH)[:16]}...")
    test_data = b"Hello, Willow!"
    hash_result = grovedb.blake3_hash(test_data)
    print(f"BLAKE3 hash: {grovedb.hash_to_hex(hash_result)[:16]}...")

    print("\n" + "=" * 50)
    print("Key Takeaways:")
    print("- All verification is done locally (trustless)")
    print("- Proofs use the GroveDB Merkle tree structure")
    print("- Root hash can be compared against consensus")
    print("- Use unverified operations only when trust is acceptable")


if __name__ == "__main__":
    asyncio.run(main())
