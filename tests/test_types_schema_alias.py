"""Regression: schema field on registration models must not shadow BaseModel.schema()."""

import warnings

from willow import (
    RegisterDatasetRequest,
    SchemaDefinition,
    SchemaField,
    SubgroveRegistration,
)


def _schema():
    return SchemaDefinition(version=1, fields={"id": SchemaField(type="string")})


def test_register_dataset_request_accepts_schema_alias():
    req = RegisterDatasetRequest(
        dataset_id="x",
        name="Test",
        owner_did="did:willow:y",
        schema=_schema(),
    )
    assert req.schema_ is not None
    assert req.schema_.version == 1


def test_register_dataset_request_serializes_with_wire_name():
    req = RegisterDatasetRequest(
        dataset_id="x",
        name="Test",
        owner_did="did:willow:y",
        schema=_schema(),
    )
    dump = req.model_dump(by_alias=True)
    assert "schema" in dump
    assert "schema_" not in dump


def test_register_dataset_request_roundtrip():
    req = RegisterDatasetRequest(
        dataset_id="x",
        name="Test",
        owner_did="did:willow:y",
        schema=_schema(),
    )
    parsed = RegisterDatasetRequest.model_validate(req.model_dump(by_alias=True))
    assert parsed.schema_ is not None
    assert parsed.schema_.version == 1


def test_subgrove_registration_accepts_schema_alias():
    sg = SubgroveRegistration(
        subgrove_id="x",
        name="Test",
        owner_did="did:willow:y",
        schema=_schema(),
        created_at=0,
        updated_at=0,
    )
    assert sg.schema_ is not None


def test_no_pydantic_field_shadow_warning_on_import():
    # If the rename regresses, Pydantic re-emits:
    #   UserWarning: Field name "schema" in "X" shadows an attribute in parent "BaseModel"
    with warnings.catch_warnings():
        warnings.simplefilter("error", UserWarning)
        import importlib

        import willow.types

        importlib.reload(willow.types)
