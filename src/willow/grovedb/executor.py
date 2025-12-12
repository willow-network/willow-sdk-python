"""
Merk Proof Stack Machine Executor

Executes Merk proof operations using a stack-based approach.
"""

from typing import Optional, List, Callable
from .types import (
    MerkOp,
    MerkNode,
    CryptoHash,
    ProvedKeyValue,
    MerkExecutionResult,
    PushOp,
    PushInvertedOp,
    ParentOp,
    ChildOp,
    ParentInvertedOp,
    ChildInvertedOp,
    KVNode,
    KVValueHashNode,
    KVDigestNode,
    KVRefValueHashNode,
    KVValueHashFeatureTypeNode,
    GroveDBVerificationError
)
from .tree import Tree, compare_bytes
from .merk_decoder import MerkDecoder
from .hash import value_hash


def execute_ops(
    ops,
    collapse: bool = True,
    visit_node: Optional[Callable[[MerkNode], None]] = None
) -> Tree:
    """
    Execute Merk proof operations and return the resulting tree.

    Args:
        ops: Iterable of MerkOp
        collapse: If True, convert children to hashes to save memory
        visit_node: Optional callback for each node

    Returns:
        The resulting tree
    """
    stack: List[Tree] = []
    last_key: Optional[bytes] = None
    last_key_inverted = False

    def pop() -> Tree:
        if not stack:
            raise GroveDBVerificationError("Stack underflow")
        return stack.pop()

    for op in ops:
        if isinstance(op, PushOp):
            # Verify key ordering (ascending)
            key = _get_node_key(op.node)
            if key and last_key and not last_key_inverted:
                if compare_bytes(key, last_key) <= 0:
                    raise GroveDBVerificationError("Incorrect key ordering")
            if key:
                last_key = key
                last_key_inverted = False

            if visit_node:
                visit_node(op.node)

            stack.append(Tree(op.node))

        elif isinstance(op, PushInvertedOp):
            # Verify key ordering (descending for inverted)
            key = _get_node_key(op.node)
            if key and last_key and last_key_inverted:
                if compare_bytes(key, last_key) >= 0:
                    raise GroveDBVerificationError("Incorrect key ordering inverted")
            if key:
                last_key = key
                last_key_inverted = True

            if visit_node:
                visit_node(op.node)

            stack.append(Tree(op.node))

        elif isinstance(op, ParentOp):
            # Pop parent and child, attach child as LEFT of parent
            parent = pop()
            child = pop()
            # Capture height before potential collapse
            child_height = child.height
            child_to_attach = child.into_hash() if collapse else child
            parent.attach_with_height(True, child_to_attach, child_height)
            stack.append(parent)

        elif isinstance(op, ChildOp):
            # Pop child and parent, attach child as RIGHT of parent
            child = pop()
            parent = pop()
            child_height = child.height
            child_to_attach = child.into_hash() if collapse else child
            parent.attach_with_height(False, child_to_attach, child_height)
            stack.append(parent)

        elif isinstance(op, ParentInvertedOp):
            # Pop parent and child, attach child as RIGHT of parent
            parent = pop()
            child = pop()
            child_height = child.height
            child_to_attach = child.into_hash() if collapse else child
            parent.attach_with_height(False, child_to_attach, child_height)
            stack.append(parent)

        elif isinstance(op, ChildInvertedOp):
            # Pop child and parent, attach child as LEFT of parent
            child = pop()
            parent = pop()
            child_height = child.height
            child_to_attach = child.into_hash() if collapse else child
            parent.attach_with_height(True, child_to_attach, child_height)
            stack.append(parent)

    if len(stack) != 1:
        raise GroveDBVerificationError(
            f"Expected proof to result in exactly one stack item, got {len(stack)}"
        )

    tree = stack[0]

    # Verify AVL tree property
    height_diff = abs(tree.child_heights[0] - tree.child_heights[1])
    if height_diff > 1:
        raise GroveDBVerificationError("Expected proof to result in a valid AVL tree")

    return tree


def execute_merk_proof(proof_bytes: bytes, collapse: bool = True) -> Tree:
    """
    Execute a Merk proof from bytes.

    Args:
        proof_bytes: The Merk proof bytes
        collapse: If True, convert children to hashes to save memory

    Returns:
        The resulting tree
    """
    decoder = MerkDecoder(proof_bytes)
    return execute_ops(decoder, collapse)


def execute_merk_proof_with_query(
    proof_bytes: bytes,
    limit: Optional[int] = None,
    left_to_right: bool = True
) -> MerkExecutionResult:
    """
    Execute a Merk proof and extract results matching a query.

    Args:
        proof_bytes: The Merk proof bytes
        limit: Optional limit on results
        left_to_right: Direction of traversal

    Returns:
        Execution result with root hash and matched values
    """
    result_set: List[ProvedKeyValue] = []
    current_limit = limit

    def visit_node(node: MerkNode) -> None:
        nonlocal current_limit

        # Check if we've hit the limit
        if current_limit is not None and current_limit <= 0:
            return

        # Extract key-value if present
        if isinstance(node, KVNode):
            result_set.append(ProvedKeyValue(
                key=node.key,
                value=node.value,
                proof=value_hash(node.value)
            ))
            if current_limit is not None:
                current_limit -= 1

        elif isinstance(node, (KVValueHashNode, KVValueHashFeatureTypeNode)):
            result_set.append(ProvedKeyValue(
                key=node.key,
                value=node.value,
                proof=node.value_hash
            ))
            if current_limit is not None:
                current_limit -= 1

        elif isinstance(node, KVRefValueHashNode):
            result_set.append(ProvedKeyValue(
                key=node.key,
                value=node.value,
                proof=node.value_hash
            ))
            if current_limit is not None:
                current_limit -= 1

        elif isinstance(node, KVDigestNode):
            # Digest has no value, just proof of existence
            result_set.append(ProvedKeyValue(
                key=node.key,
                value=None,
                proof=node.value_hash
            ))
        # Hash and KVHash don't contribute to results

    decoder = MerkDecoder(proof_bytes)
    tree = execute_ops(decoder, True, visit_node)

    return MerkExecutionResult(
        root_hash=tree.hash(),
        result_set=result_set,
        limit=current_limit
    )


def _get_node_key(node: MerkNode) -> Optional[bytes]:
    """Get the key from a node if it has one."""
    if isinstance(node, (KVNode, KVValueHashNode, KVDigestNode,
                        KVRefValueHashNode, KVValueHashFeatureTypeNode)):
        return node.key
    return None
