"""
Willow Python SDK - Proof Verification Example

Demonstrates what the SDK verifies, and how:
1. A verified read (client.data.get_verified), which raises when it can't verify
2. Checking a key's proof yourself, bound to its subgrove, key, and value
3. Pinning a verifier to a root you trust
4. Root-hash extraction (binds no key or value)
5. Unverified reads
6. Low-level grovedb module access

A proof shows a value is stored under a root hash. It proves the value
only once that root is one you trust: the app_hash of the CometBFT header
at the proof's height + 1. client.data.get reads that header from the
consensus node at consensus_rpc_url, and trusts that node (the SDK does not
verify commit signatures).

Prerequisites:
- pip install willow-sdk
- Run a local Willow node
"""

import asyncio
from willow import (
    WillowClient,
    GroveDBProofVerifier,
    ProofVerificationOptions,
    ProofVerifier,
    ProofVerificationError,
    WillowError,
    generate_did,
    grovedb,
    subgrove_data_path,
    verify_proof_quick,
)


SUBGROVE = "items"
KEY = "item-1"
# The CometBFT RPC of a node you run or trust (not the API).
CONSENSUS_RPC_URL = "http://localhost:26657"


async def main():
    print("Willow Proof Verification Demo")
    print("=" * 50)

    did_info = generate_did()

    async with WillowClient("http://localhost:3031", consensus_rpc_url=CONSENSUS_RPC_URL) as client:
        # Reads are signed by the identity, which must be a registered DID:
        # register it (pre-fund the DID with the registration fee first),
        # and wait for the registration to land before it signs anything.
        client.set_identity(did_info["did"], did_info["private_key"], did_info["public_key_id"])
        await client.wait_until_landed(await client.register_did(did_info["did_document"]))

        # 1. A verified read: the value comes back only when its proof
        #    proves it at KEY under the subgrove's data, against the
        #    consensus RPC's header for the proof's state, and that state is
        #    current (ProofHeightOutOfRangeError when it isn't).
        print("\n1. Verified Read")
        print("-" * 40)
        try:
            verified = await client.data.get_verified(SUBGROVE, KEY)
            print(f"Verified value: {verified.value}")
            print(f"Proven at header {verified.height}, root {verified.root_hash}")
        except ProofVerificationError as e:
            print(f"Not verified: {e}")
        except WillowError as e:
            print(f"Read error: {e}")

        # 2. Check a key's proof yourself
        print("\n2. Check a Proof")
        print("-" * 40)
        try:
            value = await client.data.get_unverified(SUBGROVE, KEY)
            proof = await client.proof.get(SUBGROVE, KEY)  # {proof, path, key, height, ...}
            result = ProofVerifier.verify_item_proof(
                proof["proof"], KEY, value, subgrove_data_path(SUBGROVE)
            )
            print(f"Proof binds the value to {SUBGROVE}/{KEY}: {result.valid}")
            if result.valid:
                print(f"Root it computes: {result.root_hash}")
                print(f"Compare it with the app_hash of the header at height {proof['height'] + 1}")
            else:
                print(f"Reason: {result.error}")
        except WillowError as e:
            print(f"Read error: {e}")

    # 3. Pin a verifier to a root you trust: a proof with another root is
    #    invalid
    print("\n3. Verify Against a Trusted Root")
    print("-" * 40)
    trusted_root = "a" * 64  # the app_hash of a header you trust
    pinned = GroveDBProofVerifier(ProofVerificationOptions(expected_root_hash=trusted_root))
    sample_proof = "00" + "ff" * 32  # Intentionally invalid for demo.
    result = pinned.verify_item(sample_proof, KEY, {"field": "value"}, subgrove_data_path(SUBGROVE))
    print(f"Valid: {result.valid}")
    print(f"Error: {result.error}")

    # 4. Root-hash extraction: the root a proof computes, binding nothing
    print("\n4. Root Hash Extraction")
    print("-" * 40)
    try:
        root_hash = verify_proof_quick(sample_proof)
        print(f"Root hash: {root_hash[:16]}...")
    except ProofVerificationError as e:
        print(f"Could not compute a root hash: {e}")

    # 5. Unverified reads: what the API serves
    print("\n5. Unverified Reads")
    print("-" * 40)
    async with WillowClient("http://localhost:3031") as client:
        # The DID registered above.
        client.set_identity(did_info["did"], did_info["private_key"], did_info["public_key_id"])
        try:
            result = await client.data.query_unverified(
                SUBGROVE,
                {"filters": {"status": "active"}},
            )
            print(f"Query returned {len(result.documents)} documents (not verified)")
        except Exception as e:
            print(f"Query error: {e}")

    # 6. Low-level grovedb module access
    print("\n6. Low-Level GroveDB Access")
    print("-" * 40)
    print(f"Hash length: {grovedb.HASH_LENGTH} bytes")
    print(f"Null hash: {grovedb.hash_to_hex(grovedb.NULL_HASH)[:16]}...")
    test_data = b"Hello, Willow!"
    hash_result = grovedb.blake3_hash(test_data)
    print(f"BLAKE3 hash: {grovedb.hash_to_hex(hash_result)[:16]}...")


if __name__ == "__main__":
    asyncio.run(main())
