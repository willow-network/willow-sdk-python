"""The CLI keeps the saved identity's algorithm and signs with it."""

import json

import pytest
from click.testing import CliRunner

from willow import cli


@pytest.fixture
def config_file(tmp_path, monkeypatch):
    path = tmp_path / ".willow" / "config.json"
    monkeypatch.setattr(cli, "CONFIG_FILE", path)
    return path


def test_generate_saves_the_algorithm(config_file):
    result = CliRunner().invoke(cli.cli, ["did", "generate", "--algorithm", "secp256k1", "--save"])
    assert result.exit_code == 0, result.output
    assert json.loads(config_file.read_text())["identity"]["algorithm"] == "secp256k1"
    assert cli.get_identity_or_exit()[3] == "secp256k1"


def test_login_saves_the_algorithm_and_an_older_identity_is_ed25519(config_file):
    config_file.parent.mkdir()
    config_file.write_text(json.dumps({"identity": {
        "did": "did:willow:a", "private_key": "03" * 32, "public_key_id": "did:willow:a#key-1",
    }}))
    assert cli.get_identity_or_exit()[3] == "Ed25519"

    result = CliRunner().invoke(cli.cli, ["auth", "login", "--algorithm", "secp256k1"])
    assert result.exit_code == 0, result.output
    assert cli.get_identity_or_exit() == (
        "did:willow:a", "03" * 32, "did:willow:a#key-1", "secp256k1"
    )


def test_data_commands_sign_with_the_saved_algorithm(config_file, monkeypatch):
    CliRunner().invoke(cli.cli, ["did", "generate", "--algorithm", "secp256k1", "--save"])
    identities = []

    class Client:
        def __init__(self, api_url):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        def set_identity(self, *args):
            identities.append(args)

        class data:
            @staticmethod
            async def store(subgrove_id, data):
                return []

    monkeypatch.setattr(cli, "WillowClient", Client)
    result = CliRunner().invoke(cli.cli, ["data", "store", "sg", "-"], input='{"k": {}}')
    assert result.exit_code == 0, result.output
    assert identities[0][3] == "secp256k1"
