"""Regression tests for the GroveDB envelope-descent guard (check_envelope).

The gap (grovedb 3.1.0): the verifier finds the next layer by the proof
envelope's `lower_layers` map key, which is not hash-bound. A prover who
renames or drops the entry for a subtree on the query path gets the SAME root
hash with that subtree's results silently gone, so a proof of "K = V" verifies
as "K is absent". check_envelope closes it by requiring a lower layer for every
path segment and pinning prove_options to the chain default.

These tests construct the decoded envelope directly (dataclasses), so they
exercise the guard independently of the byte decoder — see the PR note about
the decoder format.
"""
import pytest

from willow.grovedb import GroveDBVerificationError
from willow.grovedb.types import GroveDBProof, GroveDBProofV0, LayerProof, ProveOptions
from willow.grovedb.hash import bytes_to_hex
from willow.grovedb.verifier import check_envelope

PATH = [b"subgroves", b"aave-v3-lending", b"indexed", b"Supply"]


def leaf(*keys):
    return LayerProof(merk_proof=b"", lower_layers={bytes_to_hex(k): leaf() for k in keys})


def honest_envelope(path=PATH, opts=True):
    # A chain of single-child layers down the path, empty at the leaf.
    layer = LayerProof(merk_proof=b"", lower_layers={})
    for seg in reversed(path):
        layer = LayerProof(merk_proof=b"", lower_layers={bytes_to_hex(seg): layer})
    return GroveDBProof(
        version=0,
        proof=GroveDBProofV0(
            root_layer=layer,
            prove_options=ProveOptions(decrease_limit_on_empty_sub_query_result=opts),
        ),
    )


def test_honest_envelope_descends_to_the_path():
    check_envelope(honest_envelope(), PATH)


def test_renamed_lower_layer_is_rejected():
    p = honest_envelope()
    # Rename the root layer's only key: the descent for segment 0 now misses.
    root = p.proof.root_layer
    (only_key, sub), = list(root.lower_layers.items())
    root.lower_layers = {bytes_to_hex(b"forged"): sub}
    with pytest.raises(GroveDBVerificationError, match="does not descend"):
        check_envelope(p, PATH)


def test_dropped_lower_layer_is_rejected():
    p = honest_envelope()
    # Walk to the 'indexed' layer and drop its 'Supply' child.
    layer = p.proof.root_layer
    for seg in PATH[:3]:
        layer = layer.lower_layers[bytes_to_hex(seg)]
    layer.lower_layers = {}
    with pytest.raises(GroveDBVerificationError, match="does not descend"):
        check_envelope(p, PATH)


def test_extra_lower_layers_below_the_path_are_rejected():
    p = honest_envelope(path=PATH[:3])  # descends only to 'indexed'
    with pytest.raises(GroveDBVerificationError, match="unexpected lower layers"):
        check_envelope(p, PATH[:2])  # ask it to stop at 'aave-v3-lending'


def test_non_default_prove_options_is_rejected():
    with pytest.raises(GroveDBVerificationError, match="prove_options"):
        check_envelope(honest_envelope(opts=False), PATH)


def test_verify_options_expected_path_invokes_the_guard(monkeypatch):
    # verify_grovedb_proof must run check_envelope when expected_path is set.
    from willow.grovedb import verifier

    called = {}

    def fake_decode(_data):
        return honest_envelope()

    def fake_layer(*_a, **_k):
        return "root"

    monkeypatch.setattr(verifier, "decode_grovedb_proof", fake_decode)
    monkeypatch.setattr(verifier, "_verify_layer_proof", lambda *a, **k: b"\x00" * 32)
    real_check = verifier.check_envelope
    monkeypatch.setattr(verifier, "check_envelope", lambda p, path: called.setdefault("path", path) or real_check(p, path))

    verifier.verify_grovedb_proof(b"x", verifier.VerifyOptions(expected_path=PATH))
    assert called["path"] == PATH
