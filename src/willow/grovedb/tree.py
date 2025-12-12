"""
Merk Tree Data Structure

Represents the tree structure built during proof execution.
"""

from typing import Optional, Tuple, Generator, List
from dataclasses import dataclass, field
from .types import (
    MerkNode,
    CryptoHash,
    NULL_HASH,
    HashNode,
    KVHashNode,
    KVNode,
    KVValueHashNode,
    KVDigestNode,
    KVRefValueHashNode,
    KVValueHashFeatureTypeNode,
    GroveDBVerificationError
)
from .hash import kv_hash, kv_digest_to_kv_hash, node_hash, value_hash, combine_hash


@dataclass
class Child:
    """Child node with cached hash."""
    tree: "Tree"
    hash: CryptoHash


class Tree:
    """Binary tree for proof verification."""

    def __init__(self, node: MerkNode):
        """
        Initialize tree with a node.

        Args:
            node: MerkNode for this tree node
        """
        self.node = node
        self.left: Optional[Child] = None
        self.right: Optional[Child] = None
        self.height: int = 1
        self.child_heights: Tuple[int, int] = (0, 0)

    def hash(self) -> CryptoHash:
        """
        Compute the hash of this tree node.

        Returns:
            32-byte hash
        """
        # For Hash nodes, the stored hash IS the complete node hash
        if isinstance(self.node, HashNode):
            return self.node.hash

        kvh = self._compute_kv_hash()
        return node_hash(kvh, self.child_hash(True), self.child_hash(False))

    def _compute_kv_hash(self) -> CryptoHash:
        """Compute the KV hash portion based on node type."""
        node = self.node

        if isinstance(node, HashNode):
            # Should not reach here - handled in hash()
            raise GroveDBVerificationError("Hash nodes should not compute KV hash")

        elif isinstance(node, KVHashNode):
            return node.kv_hash

        elif isinstance(node, KVNode):
            return kv_hash(node.key, node.value)

        elif isinstance(node, (KVValueHashNode, KVValueHashFeatureTypeNode)):
            return kv_digest_to_kv_hash(node.key, node.value_hash)

        elif isinstance(node, KVDigestNode):
            return kv_digest_to_kv_hash(node.key, node.value_hash)

        elif isinstance(node, KVRefValueHashNode):
            # For references, combine the node's value hash with the referenced value hash
            ref_value_hash = value_hash(node.value)
            combined_value_hash = combine_hash(node.value_hash, ref_value_hash)
            return kv_digest_to_kv_hash(node.key, combined_value_hash)

        else:
            raise GroveDBVerificationError(f"Unknown node type: {type(node).__name__}")

    def child_hash(self, left: bool) -> CryptoHash:
        """
        Get the hash of a child, or NULL_HASH if no child.

        Args:
            left: True for left child, False for right child

        Returns:
            Child hash or NULL_HASH
        """
        child = self.left if left else self.right
        return child.hash if child else NULL_HASH

    def attach(self, left: bool, child: "Tree") -> None:
        """
        Attach a child to this node.

        Args:
            left: True to attach as left child, False for right
            child: Tree to attach
        """
        self.attach_with_height(left, child, child.height)

    def attach_with_height(self, left: bool, child: "Tree", original_height: int) -> None:
        """
        Attach a child to this node with explicit height.

        This is used when the child may have been collapsed (hash converted)
        and we need to preserve the original height for AVL checking.

        Args:
            left: True to attach as left child, False for right
            child: Tree to attach
            original_height: Original height before potential collapse
        """
        if left and self.left is not None:
            raise GroveDBVerificationError("Left child already attached")
        if not left and self.right is not None:
            raise GroveDBVerificationError("Right child already attached")

        self.height = max(self.height, original_height + 1)

        if left:
            self.child_heights = (original_height, self.child_heights[1])
            self.left = Child(tree=child, hash=child.hash())
        else:
            self.child_heights = (self.child_heights[0], original_height)
            self.right = Child(tree=child, hash=child.hash())

    def into_hash(self) -> "Tree":
        """
        Convert this tree to a hash-only node (for memory efficiency during execution).

        Returns:
            New Tree with just the hash
        """
        h = self.hash()
        return Tree(HashNode(hash=h))

    def get_key(self) -> Optional[bytes]:
        """
        Get the key from this node (if it has one).

        Returns:
            Key bytes or None
        """
        node = self.node
        if isinstance(node, (KVNode, KVValueHashNode, KVDigestNode,
                            KVRefValueHashNode, KVValueHashFeatureTypeNode)):
            return node.key
        return None

    def get_value(self) -> Optional[bytes]:
        """
        Get the value from this node (if it has one).

        Returns:
            Value bytes or None
        """
        node = self.node
        if isinstance(node, (KVNode, KVValueHashNode, KVRefValueHashNode,
                            KVValueHashFeatureTypeNode)):
            return node.value
        return None

    def get_value_hash(self) -> Optional[CryptoHash]:
        """
        Get the value hash from this node.

        Returns:
            Value hash or None
        """
        node = self.node
        if isinstance(node, (KVValueHashNode, KVDigestNode,
                            KVRefValueHashNode, KVValueHashFeatureTypeNode)):
            return node.value_hash
        elif isinstance(node, KVNode):
            return value_hash(node.value)
        return None

    def has_kv(self) -> bool:
        """
        Check if this node has key-value data.

        Returns:
            True if node has KV data
        """
        return not isinstance(self.node, (HashNode, KVHashNode))

    def in_order(self) -> Generator["Tree", None, None]:
        """
        In-order traversal of the tree.

        Yields:
            Tree nodes in key order
        """
        if self.left:
            yield from self.left.tree.in_order()
        yield self
        if self.right:
            yield from self.right.tree.in_order()


def compare_bytes(a: bytes, b: bytes) -> int:
    """
    Compare two byte arrays.

    Args:
        a: First bytes
        b: Second bytes

    Returns:
        -1 if a < b, 0 if equal, 1 if a > b
    """
    min_len = min(len(a), len(b))
    for i in range(min_len):
        if a[i] < b[i]:
            return -1
        if a[i] > b[i]:
            return 1
    return len(a) - len(b)
