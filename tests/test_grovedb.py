"""Comprehensive tests for the grovedb module."""

import pytest
from willow.grovedb import (
    # Types
    CryptoHash,
    HASH_LENGTH,
    NULL_HASH,
    GroveDBVerificationError,
    HashNode,
    KVHashNode,
    KVNode,
    KVValueHashNode,
    KVDigestNode,
    KVRefValueHashNode,
    KVValueHashFeatureTypeNode,
    PushOp,
    PushInvertedOp,
    ParentOp,
    ChildOp,
    ParentInvertedOp,
    ChildInvertedOp,
    BasicMerkNode,
    SummedMerkNode,
    BigSummedMerkNode,
    CountedMerkNode,
    CountedSummedMerkNode,
    ItemElement,
    ReferenceElement,
    TreeElement,
    SumTreeElement,
    LayerProof,
    GroveDBProof,
    ProvedKeyValue,
    # Varint
    encode_varint,
    decode_varint,
    decode_signed_varint,
    decode_varint64,
    decode_signed_varint64,
    VarintError,
    # Hash
    blake3_hash,
    value_hash,
    kv_hash,
    kv_digest_to_kv_hash,
    node_hash,
    combine_hash,
    hash_equals,
    is_null_hash,
    hash_to_hex,
    hex_to_hash,
    bytes_to_hex,
    hex_to_bytes,
    # Bincode
    BincodeReader,
    # Merk decoder
    MerkDecoder,
    decode_merk_ops,
    # Tree
    Tree,
    Child,
    compare_bytes,
    # Element
    deserialize_element,
    is_tree_element,
    has_root_key,
    get_tree_feature_type,
    # Executor
    execute_ops,
    execute_merk_proof,
    execute_merk_proof_with_query,
    # Verifier
    verify_grovedb_proof,
    verify_proof_against_root,
    quick_verify,
    VerifyOptions,
)


class TestTypes:
    """Test type definitions."""

    def test_hash_length(self):
        """Test HASH_LENGTH constant."""
        assert HASH_LENGTH == 32

    def test_null_hash(self):
        """Test NULL_HASH is 32 zero bytes."""
        assert len(NULL_HASH) == 32
        assert all(b == 0 for b in NULL_HASH)

    def test_hash_node(self):
        """Test HashNode creation."""
        h = bytes(32)
        node = HashNode(hash=h)
        assert node.hash == h

    def test_kv_node(self):
        """Test KVNode creation."""
        node = KVNode(key=b"test", value=b"data")
        assert node.key == b"test"
        assert node.value == b"data"

    def test_kv_value_hash_node(self):
        """Test KVValueHashNode creation."""
        node = KVValueHashNode(
            key=b"key",
            value=b"value",
            value_hash=bytes(32)
        )
        assert node.key == b"key"
        assert node.value == b"value"
        assert len(node.value_hash) == 32

    def test_push_op(self):
        """Test PushOp creation."""
        node = HashNode(hash=bytes(32))
        op = PushOp(node=node)
        assert op.node == node

    def test_parent_op(self):
        """Test ParentOp creation."""
        op = ParentOp()
        assert op is not None

    def test_basic_merk_node(self):
        """Test BasicMerkNode creation."""
        feature = BasicMerkNode()
        assert feature is not None

    def test_summed_merk_node(self):
        """Test SummedMerkNode creation."""
        feature = SummedMerkNode(sum=100)
        assert feature.sum == 100

    def test_counted_summed_merk_node(self):
        """Test CountedSummedMerkNode creation."""
        feature = CountedSummedMerkNode(count=10, sum=100)
        assert feature.count == 10
        assert feature.sum == 100

    def test_item_element(self):
        """Test ItemElement creation."""
        elem = ItemElement(value=b"test", flags=None)
        assert elem.value == b"test"
        assert elem.flags is None

    def test_tree_element(self):
        """Test TreeElement creation."""
        elem = TreeElement(root_key=b"root", flags=b"flags")
        assert elem.root_key == b"root"
        assert elem.flags == b"flags"

    def test_layer_proof(self):
        """Test LayerProof creation."""
        proof = LayerProof(merk_proof=b"proof", lower_layers={})
        assert proof.merk_proof == b"proof"
        assert proof.lower_layers == {}

    def test_proved_key_value(self):
        """Test ProvedKeyValue creation."""
        pkv = ProvedKeyValue(key=b"key", value=b"value", proof=bytes(32))
        assert pkv.key == b"key"
        assert pkv.value == b"value"


class TestVarint:
    """Test varint encoding/decoding."""

    def test_encode_varint_zero(self):
        """Test encoding zero."""
        result = encode_varint(0)
        assert result == b'\x00'

    def test_encode_varint_small(self):
        """Test encoding small values."""
        assert encode_varint(1) == b'\x01'
        assert encode_varint(127) == b'\x7f'

    def test_encode_varint_medium(self):
        """Test encoding medium values (requires 2 bytes)."""
        result = encode_varint(128)
        assert result == b'\x80\x01'
        result = encode_varint(300)
        assert result == b'\xac\x02'

    def test_encode_varint_large(self):
        """Test encoding large values."""
        result = encode_varint(16384)
        assert len(result) == 3

    def test_decode_varint_zero(self):
        """Test decoding zero."""
        value, consumed = decode_varint(b'\x00')
        assert value == 0
        assert consumed == 1

    def test_decode_varint_small(self):
        """Test decoding small values."""
        value, consumed = decode_varint(b'\x01')
        assert value == 1
        assert consumed == 1

        value, consumed = decode_varint(b'\x7f')
        assert value == 127
        assert consumed == 1

    def test_decode_varint_medium(self):
        """Test decoding medium values."""
        value, consumed = decode_varint(b'\x80\x01')
        assert value == 128
        assert consumed == 2

        value, consumed = decode_varint(b'\xac\x02')
        assert value == 300
        assert consumed == 2

    def test_decode_varint_with_offset(self):
        """Test decoding with offset."""
        data = b'\xff\xff\x80\x01\xff'
        value, consumed = decode_varint(data, offset=2)
        assert value == 128
        assert consumed == 2

    def test_decode_varint_roundtrip(self):
        """Test encode/decode roundtrip."""
        for val in [0, 1, 127, 128, 300, 16384, 1000000]:
            encoded = encode_varint(val)
            decoded, _ = decode_varint(encoded)
            assert decoded == val

    def test_decode_signed_varint_positive(self):
        """Test decoding positive signed varint."""
        # Zigzag encoding: 2 -> 1
        value, consumed = decode_signed_varint(b'\x02')
        assert value == 1

    def test_decode_signed_varint_negative(self):
        """Test decoding negative signed varint."""
        # Zigzag encoding: 1 -> -1
        value, consumed = decode_signed_varint(b'\x01')
        assert value == -1

    def test_decode_signed_varint_zero(self):
        """Test decoding zero signed varint."""
        value, consumed = decode_signed_varint(b'\x00')
        assert value == 0

    def test_decode_varint64(self):
        """Test decoding 64-bit varint."""
        value, consumed = decode_varint64(b'\x80\x01')
        assert value == 128

    def test_decode_signed_varint64(self):
        """Test decoding 64-bit signed varint."""
        value, consumed = decode_signed_varint64(b'\x01')
        assert value == -1

    def test_varint_too_long(self):
        """Test that overly long varints raise error."""
        # More than 5 continuation bytes
        data = b'\x80\x80\x80\x80\x80\x80'
        with pytest.raises(VarintError, match="too long"):
            decode_varint(data)

    def test_varint_unexpected_end(self):
        """Test that truncated varints raise error."""
        data = b'\x80'  # Continuation bit set but no more bytes
        with pytest.raises(VarintError, match="Unexpected end"):
            decode_varint(data)

    def test_encode_negative_raises(self):
        """Test that encoding negative values raises error."""
        with pytest.raises(VarintError):
            encode_varint(-1)


class TestHash:
    """Test hash functions."""

    def test_blake3_hash_length(self):
        """Test blake3 produces 32-byte hash."""
        result = blake3_hash(b"test")
        assert len(result) == 32

    def test_blake3_hash_deterministic(self):
        """Test blake3 is deterministic."""
        result1 = blake3_hash(b"test")
        result2 = blake3_hash(b"test")
        assert result1 == result2

    def test_blake3_hash_different_inputs(self):
        """Test different inputs produce different hashes."""
        result1 = blake3_hash(b"test1")
        result2 = blake3_hash(b"test2")
        assert result1 != result2

    def test_value_hash(self):
        """Test value_hash function."""
        result = value_hash(b"test")
        assert len(result) == 32

    def test_kv_hash(self):
        """Test kv_hash function."""
        result = kv_hash(b"key", b"value")
        assert len(result) == 32

    def test_kv_digest_to_kv_hash(self):
        """Test kv_digest_to_kv_hash function."""
        val_hash = blake3_hash(b"value")
        result = kv_digest_to_kv_hash(b"key", val_hash)
        assert len(result) == 32

    def test_node_hash(self):
        """Test node_hash function."""
        kv = bytes(32)
        left = bytes(32)
        right = bytes(32)
        result = node_hash(kv, left, right)
        assert len(result) == 32

    def test_combine_hash(self):
        """Test combine_hash function."""
        a = blake3_hash(b"a")
        b = blake3_hash(b"b")
        result = combine_hash(a, b)
        assert len(result) == 32

    def test_hash_equals_same(self):
        """Test hash_equals with same hashes."""
        h = blake3_hash(b"test")
        assert hash_equals(h, h) is True

    def test_hash_equals_different(self):
        """Test hash_equals with different hashes."""
        h1 = blake3_hash(b"test1")
        h2 = blake3_hash(b"test2")
        assert hash_equals(h1, h2) is False

    def test_hash_equals_different_length(self):
        """Test hash_equals with different lengths."""
        assert hash_equals(b"short", bytes(32)) is False

    def test_is_null_hash_true(self):
        """Test is_null_hash with null hash."""
        assert is_null_hash(NULL_HASH) is True
        assert is_null_hash(bytes(32)) is True

    def test_is_null_hash_false(self):
        """Test is_null_hash with non-null hash."""
        h = blake3_hash(b"test")
        assert is_null_hash(h) is False

    def test_hash_to_hex(self):
        """Test hash_to_hex conversion."""
        h = bytes(32)
        result = hash_to_hex(h)
        assert result == "00" * 32

    def test_hex_to_hash(self):
        """Test hex_to_hash conversion."""
        hex_str = "ab" * 32
        result = hex_to_hash(hex_str)
        assert len(result) == 32
        assert result == bytes.fromhex(hex_str)

    def test_hex_to_hash_with_0x(self):
        """Test hex_to_hash with 0x prefix."""
        hex_str = "0x" + "cd" * 32
        result = hex_to_hash(hex_str)
        assert len(result) == 32

    def test_hex_to_hash_invalid_length(self):
        """Test hex_to_hash with invalid length."""
        with pytest.raises(GroveDBVerificationError, match="Invalid hash hex length"):
            hex_to_hash("abcd")

    def test_bytes_to_hex(self):
        """Test bytes_to_hex conversion."""
        result = bytes_to_hex(b"\xab\xcd")
        assert result == "abcd"

    def test_hex_to_bytes(self):
        """Test hex_to_bytes conversion."""
        result = hex_to_bytes("abcd")
        assert result == b"\xab\xcd"

    def test_hex_to_bytes_with_0x(self):
        """Test hex_to_bytes with 0x prefix."""
        result = hex_to_bytes("0xabcd")
        assert result == b"\xab\xcd"


class TestBincode:
    """Test bincode decoding."""

    def test_bincode_reader_read_u8(self):
        """Test reading u8."""
        reader = BincodeReader(b"\x42\xff")
        assert reader.read_u8() == 0x42
        assert reader.read_u8() == 0xff

    def test_bincode_reader_read_u16(self):
        """Test reading big-endian u16."""
        reader = BincodeReader(b"\x01\x02")
        assert reader.read_u16() == 0x0102

    def test_bincode_reader_read_u32(self):
        """Test reading big-endian u32."""
        reader = BincodeReader(b"\x01\x02\x03\x04")
        assert reader.read_u32() == 0x01020304

    def test_bincode_reader_read_u64(self):
        """Test reading big-endian u64."""
        reader = BincodeReader(b"\x00\x00\x00\x00\x00\x00\x01\x00")
        assert reader.read_u64() == 256

    def test_bincode_reader_read_bool(self):
        """Test reading boolean."""
        reader = BincodeReader(b"\x00\x01")
        assert reader.read_bool() is False
        assert reader.read_bool() is True

    def test_bincode_reader_read_bool_invalid(self):
        """Test reading invalid boolean."""
        reader = BincodeReader(b"\x02")
        with pytest.raises(GroveDBVerificationError, match="Invalid boolean"):
            reader.read_bool()

    def test_bincode_reader_read_bytes(self):
        """Test reading length-prefixed bytes."""
        # u64 length (3) + 3 bytes
        data = b"\x00\x00\x00\x00\x00\x00\x00\x03abc"
        reader = BincodeReader(data)
        result = reader.read_bytes()
        assert result == b"abc"

    def test_bincode_reader_position(self):
        """Test position tracking."""
        reader = BincodeReader(b"\x01\x02\x03")
        assert reader.position() == 0
        reader.read_u8()
        assert reader.position() == 1

    def test_bincode_reader_has_more(self):
        """Test has_more check."""
        reader = BincodeReader(b"\x01")
        assert reader.has_more() is True
        reader.read_u8()
        assert reader.has_more() is False

    def test_bincode_reader_read_past_end(self):
        """Test reading past end raises error."""
        reader = BincodeReader(b"\x01")
        reader.read_u8()
        with pytest.raises(GroveDBVerificationError, match="Unexpected end"):
            reader.read_u8()


class TestMerkDecoder:
    """Test Merk operation decoding."""

    def test_decode_push_hash(self):
        """Test decoding Push(Hash) operation."""
        # Op code 0x01 + 32 byte hash
        data = bytes([0x01]) + bytes(32)
        decoder = MerkDecoder(data)
        op = decoder.next()

        assert isinstance(op, PushOp)
        assert isinstance(op.node, HashNode)
        assert len(op.node.hash) == 32

    def test_decode_push_kv(self):
        """Test decoding Push(KV) operation."""
        # Op code 0x03 + key_len(1) + key + value_len(2, big-endian) + value
        key = b"key"
        value = b"value"
        data = bytes([0x03, len(key)]) + key + len(value).to_bytes(2, 'big') + value
        decoder = MerkDecoder(data)
        op = decoder.next()

        assert isinstance(op, PushOp)
        assert isinstance(op.node, KVNode)
        assert op.node.key == key
        assert op.node.value == value

    def test_decode_parent_op(self):
        """Test decoding Parent operation."""
        data = bytes([0x10])
        decoder = MerkDecoder(data)
        op = decoder.next()
        assert isinstance(op, ParentOp)

    def test_decode_child_op(self):
        """Test decoding Child operation."""
        data = bytes([0x11])
        decoder = MerkDecoder(data)
        op = decoder.next()
        assert isinstance(op, ChildOp)

    def test_decode_parent_inverted_op(self):
        """Test decoding ParentInverted operation."""
        data = bytes([0x12])
        decoder = MerkDecoder(data)
        op = decoder.next()
        assert isinstance(op, ParentInvertedOp)

    def test_decode_child_inverted_op(self):
        """Test decoding ChildInverted operation."""
        data = bytes([0x13])
        decoder = MerkDecoder(data)
        op = decoder.next()
        assert isinstance(op, ChildInvertedOp)

    def test_decode_push_inverted_hash(self):
        """Test decoding PushInverted(Hash) operation."""
        data = bytes([0x08]) + bytes(32)
        decoder = MerkDecoder(data)
        op = decoder.next()

        assert isinstance(op, PushInvertedOp)
        assert isinstance(op.node, HashNode)

    def test_decoder_has_more(self):
        """Test has_more check."""
        data = bytes([0x10, 0x11])
        decoder = MerkDecoder(data)

        assert decoder.has_more() is True
        decoder.next()
        assert decoder.has_more() is True
        decoder.next()
        assert decoder.has_more() is False

    def test_decoder_returns_none_at_end(self):
        """Test decoder returns None at end."""
        decoder = MerkDecoder(b"")
        assert decoder.next() is None

    def test_decoder_iterator(self):
        """Test decoder as iterator."""
        data = bytes([0x10, 0x11])
        decoder = MerkDecoder(data)
        ops = list(decoder)

        assert len(ops) == 2
        assert isinstance(ops[0], ParentOp)
        assert isinstance(ops[1], ChildOp)

    def test_decode_merk_ops_function(self):
        """Test decode_merk_ops helper function."""
        data = bytes([0x10, 0x11])
        ops = decode_merk_ops(data)

        assert len(ops) == 2

    def test_unknown_op_code(self):
        """Test unknown op code raises error."""
        data = bytes([0xff])
        decoder = MerkDecoder(data)
        with pytest.raises(GroveDBVerificationError, match="Unknown op code"):
            decoder.next()


class TestTree:
    """Test tree data structure."""

    def test_tree_creation(self):
        """Test creating a tree node."""
        node = HashNode(hash=bytes(32))
        tree = Tree(node)
        assert tree.node == node
        assert tree.left is None
        assert tree.right is None
        assert tree.height == 1

    def test_tree_hash_of_hash_node(self):
        """Test hash of HashNode returns stored hash."""
        h = blake3_hash(b"test")
        node = HashNode(hash=h)
        tree = Tree(node)
        assert tree.hash() == h

    def test_tree_attach(self):
        """Test attaching children."""
        parent_node = KVNode(key=b"parent", value=b"pval")
        child_node = HashNode(hash=bytes(32))

        parent = Tree(parent_node)
        child = Tree(child_node)

        parent.attach(True, child)  # Attach as left child

        assert parent.left is not None
        assert parent.left.tree == child
        assert parent.right is None

    def test_tree_attach_with_height(self):
        """Test attaching with explicit height."""
        parent_node = KVNode(key=b"parent", value=b"pval")
        child_node = HashNode(hash=bytes(32))

        parent = Tree(parent_node)
        child = Tree(child_node)

        parent.attach_with_height(False, child, 5)  # Attach as right child

        assert parent.right is not None
        assert parent.height == 6  # max(1, 5+1)
        assert parent.child_heights[1] == 5

    def test_tree_attach_twice_fails(self):
        """Test attaching to same side twice fails."""
        parent = Tree(KVNode(key=b"p", value=b"v"))
        child1 = Tree(HashNode(hash=bytes(32)))
        child2 = Tree(HashNode(hash=bytes(32)))

        parent.attach(True, child1)
        with pytest.raises(GroveDBVerificationError, match="already attached"):
            parent.attach(True, child2)

    def test_tree_into_hash(self):
        """Test converting tree to hash node."""
        node = KVNode(key=b"key", value=b"value")
        tree = Tree(node)
        hash_tree = tree.into_hash()

        assert isinstance(hash_tree.node, HashNode)
        assert hash_tree.node.hash == tree.hash()

    def test_tree_get_key(self):
        """Test getting key from tree."""
        node = KVNode(key=b"testkey", value=b"val")
        tree = Tree(node)
        assert tree.get_key() == b"testkey"

    def test_tree_get_key_hash_node(self):
        """Test getting key from hash node returns None."""
        node = HashNode(hash=bytes(32))
        tree = Tree(node)
        assert tree.get_key() is None

    def test_tree_get_value(self):
        """Test getting value from tree."""
        node = KVNode(key=b"k", value=b"testvalue")
        tree = Tree(node)
        assert tree.get_value() == b"testvalue"

    def test_tree_has_kv(self):
        """Test has_kv check."""
        kv_tree = Tree(KVNode(key=b"k", value=b"v"))
        hash_tree = Tree(HashNode(hash=bytes(32)))

        assert kv_tree.has_kv() is True
        assert hash_tree.has_kv() is False

    def test_tree_child_hash_null(self):
        """Test child_hash returns NULL_HASH for missing child."""
        tree = Tree(KVNode(key=b"k", value=b"v"))
        assert tree.child_hash(True) == NULL_HASH
        assert tree.child_hash(False) == NULL_HASH

    def test_compare_bytes_equal(self):
        """Test comparing equal bytes."""
        assert compare_bytes(b"abc", b"abc") == 0

    def test_compare_bytes_less(self):
        """Test comparing less bytes."""
        assert compare_bytes(b"abc", b"abd") < 0
        assert compare_bytes(b"ab", b"abc") < 0

    def test_compare_bytes_greater(self):
        """Test comparing greater bytes."""
        assert compare_bytes(b"abd", b"abc") > 0
        assert compare_bytes(b"abcd", b"abc") > 0


class TestElement:
    """Test element deserialization."""

    def test_is_tree_element_true(self):
        """Test is_tree_element for tree types."""
        assert is_tree_element(TreeElement(root_key=None, flags=None)) is True
        assert is_tree_element(SumTreeElement(root_key=None, sum_value=0, flags=None)) is True

    def test_is_tree_element_false(self):
        """Test is_tree_element for non-tree types."""
        assert is_tree_element(ItemElement(value=b"test", flags=None)) is False

    def test_has_root_key_true(self):
        """Test has_root_key when root key exists."""
        elem = TreeElement(root_key=b"root", flags=None)
        assert has_root_key(elem) is True

    def test_has_root_key_false(self):
        """Test has_root_key when root key is None."""
        elem = TreeElement(root_key=None, flags=None)
        assert has_root_key(elem) is False

    def test_has_root_key_non_tree(self):
        """Test has_root_key for non-tree element."""
        elem = ItemElement(value=b"test", flags=None)
        assert has_root_key(elem) is False

    def test_get_tree_feature_type(self):
        """Test get_tree_feature_type."""
        assert get_tree_feature_type(TreeElement(root_key=None, flags=None)) == "BasicMerkNode"
        assert get_tree_feature_type(SumTreeElement(root_key=None, sum_value=0, flags=None)) == "SummedMerkNode"
        assert get_tree_feature_type(ItemElement(value=b"", flags=None)) is None


class TestExecutor:
    """Test Merk proof executor."""

    def test_execute_single_push(self):
        """Test executing single push operation."""
        node = HashNode(hash=bytes(32))
        ops = [PushOp(node=node)]

        tree = execute_ops(ops, collapse=False)
        assert isinstance(tree.node, HashNode)

    def test_execute_parent_child(self):
        """Test executing parent-child relationship."""
        # Push two nodes, then Parent (attach first as left child of second)
        node1 = HashNode(hash=blake3_hash(b"child"))
        node2 = KVNode(key=b"parent", value=b"val")
        ops = [
            PushOp(node=node1),
            PushOp(node=node2),
            ParentOp()
        ]

        tree = execute_ops(ops, collapse=False)
        assert tree.left is not None
        assert tree.right is None

    def test_execute_empty_stack_error(self):
        """Test error on empty stack operations."""
        ops = [ParentOp()]  # No nodes to operate on

        with pytest.raises(GroveDBVerificationError, match="Stack underflow"):
            execute_ops(ops)

    def test_execute_multiple_stack_items_error(self):
        """Test error when multiple items remain on stack."""
        node1 = HashNode(hash=bytes(32))
        node2 = HashNode(hash=blake3_hash(b"other"))
        ops = [PushOp(node=node1), PushOp(node=node2)]

        with pytest.raises(GroveDBVerificationError, match="exactly one stack item"):
            execute_ops(ops)

    def test_execute_merk_proof_with_query(self):
        """Test execute_merk_proof_with_query returns result."""
        # Single hash node proof
        data = bytes([0x01]) + bytes(32)
        result = execute_merk_proof_with_query(data)

        assert result.root_hash is not None
        assert len(result.root_hash) == 32
        assert isinstance(result.result_set, list)


class TestVerifier:
    """Test proof verifier."""

    def test_verify_options_defaults(self):
        """Test VerifyOptions defaults."""
        opts = VerifyOptions()
        assert opts.limit is None
        assert opts.deserialize_elements is True

    def test_verify_options_custom(self):
        """Test VerifyOptions with custom values."""
        opts = VerifyOptions(limit=10, deserialize_elements=False)
        assert opts.limit == 10
        assert opts.deserialize_elements is False

    def test_quick_verify_invalid_proof(self):
        """Test quick_verify with invalid proof."""
        with pytest.raises(GroveDBVerificationError):
            quick_verify(b"invalid")

    def test_verify_grovedb_proof_invalid(self):
        """Test verify_grovedb_proof with invalid proof."""
        with pytest.raises(GroveDBVerificationError):
            verify_grovedb_proof(b"invalid")

    def test_verify_proof_against_root_invalid(self):
        """Test verify_proof_against_root with invalid proof."""
        with pytest.raises(GroveDBVerificationError):
            verify_proof_against_root(b"invalid", bytes(32))
